package net.minestom.server.message;

import net.kyori.adventure.chat.SignedMessage;
import net.kyori.adventure.identity.Identity;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.minestom.server.MinecraftServer;
import net.minestom.server.ServerFlag;
import net.minestom.server.adventure.audience.PacketGroupingAudience;
import net.minestom.server.crypto.FilterMask;
import net.minestom.server.crypto.MessageSignature;
import net.minestom.server.crypto.SignatureValidator;
import net.minestom.server.crypto.SignedMessageBody;
import net.minestom.server.entity.Player;
import net.minestom.server.network.packet.client.play.ClientChatMessagePacket;
import net.minestom.server.network.packet.server.play.DisguisedChatPacket;
import net.minestom.server.network.packet.server.play.PlayerChatMessagePacket;
import net.minestom.server.network.packet.server.play.SystemChatPacket;
import net.minestom.server.registry.RegistryKey;
import net.minestom.server.utils.PacketSendingUtils;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.*;

/**
 * Utility class to handle client chat settings.
 */
public final class Messenger {
    /**
     * The message sent to the client if they send a chat message, but it is rejected by the server.
     */
    public static final Component CANNOT_SEND_MESSAGE = Component.translatable("chat.disabled.options", NamedTextColor.RED);
    private static final UUID NO_SENDER = new UUID(0, 0);
    private static final SystemChatPacket CANNOT_SEND_PACKET = new SystemChatPacket(CANNOT_SEND_MESSAGE, false);
    private static int GLOBAL_MESSAGE_INDEX = 0;

    /**
     * Sends a message to a player, respecting their chat settings.
     *
     * @param player   the player
     * @param message  the message
     * @return if the message was sent
     */
    public static boolean sendSystemMessage(Player player, Component message) {
        if (getChatMessageType(player).accepts(ChatPosition.SYSTEM_MESSAGE)) {
            player.sendPacket(new SystemChatPacket(message, false));
            return true;
        }
        return false;
    }


    /**
     * Sends a message to some players, respecting their chat settings.
     *
     * @param players  the players
     * @param message  the message
     * @param position the position
     */
    public static void sendSystemMessage(Collection<Player> players, Component message,
                                         ChatPosition position) {
        PacketSendingUtils.sendGroupedPacket(players, new SystemChatPacket(message, false),
                player -> getChatMessageType(player).accepts(position));
    }

    /**
     * Sends a 'disguised' message to a player. A disguised message is one that is not signed, but has a source, generally from a command like /whisper or /tell.
     * <p></p>
     * The {@link ChatType} is automatically specified as {@link ChatType#CHAT}.
     * @param receiver The player to receive the message
     * @param sender The player who sent the message
     * @param message The message contents
     * @return true, indicating the packet was sent, or false indicating it wasn't sent (due to player chat settings)
     */
    public static boolean sendDisguisedMessage(Player receiver, Player sender, Component message) {
        return sendDisguisedMessage(receiver, sender, message, ChatType.CHAT);
    }

    /**
     * Sends a 'disguised' message to a player. A disguised message is one that is not signed, but has a source, generally from a command like /whisper or /tell.
     * @param receiver The player to receive the message
     * @param sender The player who sent the message
     * @param message The message contents
     * @param chatType The chat type of disguised command
     * @return true, indicating the packet was sent, or false indicating it wasn't sent (due to player chat settings)
     */
    public static boolean sendDisguisedMessage(Player receiver, Player sender, Component message, RegistryKey<ChatType> chatType) {
        int chatTypeId = MinecraftServer.getChatTypeRegistry().getId(chatType);
        return sendDisguisedMessage(receiver, Component.text(sender.getUsername()), chatTypeId, message);
    }

    /**
     * Sends a 'disguised' message to a player. A disguised message is one that is not signed, but has a source, generally from a command like /whisper or /tell.
     * @param receiver The player to receive the message
     * @param senderName A component representing the sender's name
     * @param message The message contents
     * @param chatTypeId The {@link ChatType}'s id in the registry
     * @return true, indicating the packet was sent, or false indicating it wasn't sent (due to player chat settings)
     */
    public static boolean sendDisguisedMessage(Player receiver, Component senderName, int chatTypeId, Component message) {
        if (getChatMessageType(receiver).accepts(ChatPosition.CHAT)) {
            receiver.sendPacket(new DisguisedChatPacket(message, chatTypeId, senderName, Component.text(receiver.getUsername())));
            return true;
        }
        return false;
    }

    public static void sendSignedMessage(Collection<Player> receivers, Player sender, Component message, ClientChatMessagePacket chatPacket) {
        if (ServerFlag.ENFORCE_SECURE_CHAT) {
            // Validate that no funny business is going on
            var publicKey = sender.getPlayerConnection().playerPublicKey();
            if (publicKey == null) {
                // TODO Kick player?
                return;
            }
            var validator = SignatureValidator.from(sender);
            // From the wiki:
            //The number 1 as a 4-byte int. Always 00 00 00 01.
            //The player's 16 byte UUID.
            //The chat session (a 16 byte UUID generated randomly generated by the client).
            //The index of the message within this chat session as a 4-byte int. First message is 0, next message is 1, etc. Incremented each time the client sends a chat message.
            //The salt (from above) as a 8-byte long.
            //        The timestamp (from above) converted from millisecods to seconds, so divide by 1000, as a 8-byte long.
            //        The length of the message in bytes (from above) as a 4-byte int.
            //        The message bytes.
            //The number of messages in the last seen set, as a 4-byte int. Always in the range [0,20].
            //For each message in the last seen set, from oldest to newest, the 256 byte signature of that message.

            // Update and retrieve last seen messages
            sender.updateLastSeenList(chatPacket.ackOffset());
            List<MessageSignature> signatures = sender.getLastSeenFromBitSet(chatPacket.ackList());
            if (signatures.isEmpty() && chatPacket.ackList().cardinality() > 0) {
                // Invalid indexing into last seen list, bail out
                // TODO Kick?
                return;
            }

            int payloadSize = 4 + 16 + 16 + 4 + 8 + 8 + 4 + chatPacket.message().getBytes().length + 4 + chatPacket.ackList().cardinality() * 256;
            ByteBuffer buffer = ByteBuffer.allocateDirect(payloadSize);
            buffer.putInt(1);
            buffer.putLong(sender.getUuid().getMostSignificantBits());
            buffer.putLong(sender.getUuid().getLeastSignificantBits());
            buffer.putLong(sender.getPlayerConnection().sessionId().getMostSignificantBits());
            buffer.putLong(sender.getPlayerConnection().sessionId().getLeastSignificantBits());
            buffer.putInt(sender.chatSessionIndex());
            buffer.putLong(chatPacket.timestamp() / 1000);
            buffer.putInt(chatPacket.message().getBytes().length);
            buffer.put(chatPacket.message().getBytes());
            buffer.putInt(chatPacket.ackList().cardinality());
            for (MessageSignature signature : signatures) {
                buffer.put(signature.signature());
            }

            boolean validSignature = validator.validate(buffer.array(), chatPacket.signature());
            if (!validSignature) {
                // TODO Kick player?
                return;
            }
        }
        // Build chat message packet
        int chatTypeId = MinecraftServer.getChatTypeRegistry().getId(ChatType.CHAT);
        int globalIndex = GLOBAL_MESSAGE_INDEX++;
        SignedMessageBody.Packed packed = new SignedMessageBody.Packed(chatPacket.message(), Instant.ofEpochMilli(chatPacket.timestamp()), chatPacket.salt(), sender.getLastSeenPacked());
        PlayerChatMessagePacket chatMessagePacket = new PlayerChatMessagePacket(globalIndex, sender.getUuid(), sender.chatSessionIndex(),
                chatPacket.signature(), packed, message, new FilterMask(FilterMask.Type.PASS_THROUGH, new BitSet()),
                chatTypeId, Component.text(sender.getUsername()), null);
        sender.incrementChatSessionIndex();
        for (Player player : receivers) {
            if (canReceiveMessage(player)) {
                player.sendPacket(chatMessagePacket.copyWithTargetNameChange(component -> Component.text(player.getUsername())));
                player.addToPendingSeenMessages(chatPacket.signature());
            }
        }
    }

    /**
     * Checks if the server should receive messages from a player, given their chat settings.
     *
     * @param player the player
     * @return if the server should receive messages from them
     */
    public static boolean canReceiveMessage(Player player) {
        return getChatMessageType(player) == ChatMessageType.FULL;
    }

    /**
     * Checks if the server should receive commands from a player, given their chat settings.
     *
     * @param player the player
     * @return if the server should receive commands from them
     */
    public static boolean canReceiveCommand(Player player) {
        return getChatMessageType(player) != ChatMessageType.NONE;
    }

    /**
     * Sends a message to the player informing them we are rejecting their message or command.
     *
     * @param player the player
     */
    public static void sendRejectionMessage(Player player) {
        player.sendPacket(CANNOT_SEND_PACKET);
    }

    /**
     * Gets the chat message type for a player, returning {@link ChatMessageType#FULL} if not set.
     *
     * @param player the player
     * @return the chat message type
     */
    private static ChatMessageType getChatMessageType(Player player) {
        return Objects.requireNonNullElse(player.getSettings().chatMessageType(), ChatMessageType.FULL);
    }
}
