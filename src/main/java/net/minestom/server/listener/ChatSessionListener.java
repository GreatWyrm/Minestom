package net.minestom.server.listener;

import net.minestom.server.entity.Player;
import net.minestom.server.network.packet.client.play.ClientChatSessionUpdatePacket;

public class ChatSessionListener {

    public static void sessionListener(ClientChatSessionUpdatePacket packet, Player player) {
        player.getPlayerConnection().setChatSession(packet.chatSession());
        player.resetChatSession();
    }
}
