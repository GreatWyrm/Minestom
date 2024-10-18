package net.minestom.server.network.packet.server.play;

import net.minestom.server.network.NetworkBuffer;
import net.minestom.server.network.NetworkBufferTemplate;
import net.minestom.server.network.packet.server.ServerPacket;
import net.minestom.server.recipe.Recipe;
import net.minestom.server.recipe.RecipeSerializers;
import net.minestom.server.utils.NamespaceID;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.Map;

public record DeclareRecipesPacket(@NotNull Map<NamespaceID, List<Integer>> specialItemProperties, @NotNull List<Recipe.RecipeEntry> recipeEntries) implements ServerPacket.Play {
    public static final int MAX_SPECIAL_PROPERTIES = Short.MAX_VALUE;

    public static final NetworkBuffer.Type<DeclareRecipesPacket> SERIALIZER = NetworkBufferTemplate.template(
            NetworkBuffer.STRING.transform(NamespaceID::from, Object::toString).mapValue(NetworkBuffer.VAR_INT.list(MAX_SPECIAL_PROPERTIES), MAX_SPECIAL_PROPERTIES), DeclareRecipesPacket::specialItemProperties,
            RecipeSerializers.RECIPE_ENTRY.list(MAX_SPECIAL_PROPERTIES), DeclareRecipesPacket::recipeEntries,
            DeclareRecipesPacket::new);

    public DeclareRecipesPacket {
        specialItemProperties = Map.copyOf(specialItemProperties);
        recipeEntries = List.copyOf(recipeEntries);
    }
}
