package net.minestom.server.effects;

/**
 * World Events available in Minecraft Vanilla
 */
public enum WorldEvent {

    DISPENSER_DISPENSES(1000),
    DISPENSER_FAILS_TO_DISPENSE(1001),
    DISPENSER_SHOOTS(1002),
    ENDER_EYE_LAUNCHED(1003),
    FIREWORK_SHOT(1004),
    FIRE_EXTINGUISHED(1009),
    PLAY_RECORD(1010),
    STOP_RECORD(1011),
    GHAST_WARNS(1015),
    GHAST_SHOOTS(1016),
    ENDERDRAGON_SHOOTS(1017),
    BLAZE_SHOOTS(1018),
    ZOMBIE_ATTACKS_WOOD_DOOR(1019),
    ZOMBIE_ATTACKS_IRON_DOOR(1020),
    ZOMBIE_BREAKS_WOOD_DOOR(1021),
    WITHER_BREAKS_BLOCK(1022),
    WITHER_SPAWNED(1023),
    WITHER_SHOOTS(1024),
    BAT_TAKES_OFF(1025),
    ZOMBIE_INFECTS(1026),
    ZOMBIE_VILLAGER_CONVERTED(1027),
    ENDER_DRAGON_DEATH(1028),
    ANVIL_DESTROYED(1029),
    ANVIL_USED(1030),
    ANVIL_LANDED(1031),
    PORTAL_TRAVEL(1032),
    CHORUS_FLOWER_GROWN(1033),
    CHORUS_FLOWER_DIED(1034),
    BREWING_STAND_BREWED(1035),
    IRON_TRAPDOOR_OPENED(1036),
    IRON_TRAPDOOR_CLOSED(1037),
    END_PORTAL_CREATED_IN_OVERWORLD(1038),
    PHANTOM_BITES(1039),
    ZOMBIE_CONVERTS_TO_DROWNED(1040),
    HUSK_CONVERTS_TO_ZOMBIE_BY_DROWNING(1041),
    GRINDSTONE_USED(1042),
    BOOK_PAGE_TURNED(1043),
    SMITHING_TABLE_USED(1044),
    POINTED_DRIPSTONE_LANDING(1045),
    LAVA_DRIP_CAULDRON_DRIPSTONE(1046),
    WATER_DRIP_CAULDRON_DRIPSTONE(1047),
    SKELETON_CONVERTS_STRAY(1048),
    CRAFTER_SUCCESSFULLY_CRAFT(1049),
    CRAFTER_FAILED_CRAFT(1050),

// Particles

    COMPOSTER_COMPOSTS(1500),
    LAVA_CONVERTS_BLOCK(1501),
    REDSTONE_TORCH_BURNS_OUT(1502),
    ENDER_EYE_PLACED(1503),
    FLUID_DRIPS_DRIPSTONE(1504),
    BONEMEAL_PARTICLES(1505),

    SPAWNS_10_SMOKE_PARTICLES(2000),
    BLOCK_BREAK(2001),
    SPLASH_POTION(2002),
    EYE_OF_ENDER_ENTITY_BREAK_ANIMATION(2003),
    MOB_SPAWN_PARTICLE_EFFECT(2004),
    DRAGON_BREATH(2006),
    INSTANT_SPLASH_POTION(2007),
    ENDER_DRAGON_DESTROYS_BLOCK(2008),
    WET_SPONGE_VAPORIZES(2009),

    END_GATEWAY_SPAWN(3000),
    ENDERDRAGON_GROWL(3001),
    ELECTRIC_SPARK(3002),
    COPPER_APPLY_WAX(3003),
    COPPER_REMOVE_WAX(3004),
    COPPER_SCRAPE_OXIDATION(3005)
    ;

    private final int id;

    WorldEvent(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }
}