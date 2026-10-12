/**
 * 256 short, distinct, lowercase English words — one per byte of the pairing
 * safety code. Order is part of the protocol (abra-sync-sas-v1): never reorder
 * or edit; add a new list + domain string instead.
 */
export const SAS_WORDS: readonly string[] = Object.freeze([
  "acid", "acorn", "actor", "adobe", "agent", "alarm", "album", "alley",
  "amber", "anchor", "angle", "ankle", "apple", "apron", "arena", "arrow",
  "aspen", "atlas", "attic", "audio", "badge", "bagel", "baker", "bamboo",
  "banjo", "barn", "basil", "beach", "beacon", "beard", "bench", "berry",
  "bison", "blade", "blimp", "bloom", "board", "bonus", "boots", "brain",
  "brass", "bread", "brick", "bridge", "brook", "brush", "bucket", "buffalo",
  "bugle", "cabin", "cable", "cactus", "camel", "canal", "candle", "canoe",
  "canyon", "carbon", "cargo", "carpet", "castle", "cedar", "cello", "chalk",
  "cherry", "chess", "chief", "chimney", "cider", "cinema", "circus", "citrus",
  "clock", "cloud", "clover", "cobalt", "cocoa", "comet", "copper", "coral",
  "cotton", "cougar", "crane", "crater", "crayon", "cricket", "crown", "cube",
  "dahlia", "daisy", "delta", "denim", "desert", "diamond", "dingo", "dolphin",
  "domino", "donkey", "dragon", "drum", "eagle", "easel", "echo", "eclipse",
  "elbow", "elder", "ember", "engine", "falcon", "fable", "feather", "fence",
  "fern", "ferry", "fiddle", "fig", "flame", "flask", "flute", "forest",
  "fossil", "fox", "frost", "galaxy", "garden", "garlic", "gazelle", "geyser",
  "ginger", "glacier", "globe", "goat", "gopher", "granite", "grape", "gravel",
  "guitar", "hammer", "harbor", "harp", "hazel", "helmet", "heron", "hippo",
  "honey", "hornet", "husky", "igloo", "indigo", "iris", "island", "ivory",
  "jacket", "jaguar", "jasmine", "jelly", "jigsaw", "jungle", "kayak", "kettle",
  "kiwi", "koala", "ladder", "lagoon", "lantern", "lemon", "lentil", "lily",
  "lizard", "llama", "lobster", "locket", "lotus", "magnet", "mango", "maple",
  "marble", "meadow", "melon", "meteor", "mint", "mirror", "mitten", "monsoon",
  "moose", "mosaic", "muffin", "nectar", "needle", "nickel", "nutmeg", "oasis",
  "ocean", "olive", "onion", "orbit", "orchid", "otter", "oyster", "paddle",
  "panda", "papaya", "parrot", "peanut", "pebble", "pelican", "pepper", "piano",
  "pickle", "pigeon", "pillow", "pine", "planet", "plum", "pony", "poppy",
  "prism", "pumpkin", "puzzle", "quartz", "quill", "rabbit", "radar", "radish",
  "raven", "reef", "ribbon", "river", "robin", "rocket", "saddle", "salmon",
  "sandal", "saturn", "scarf", "shovel", "sierra", "silver", "sketch", "sloth",
  "socket", "spider", "sponge", "spruce", "squid", "statue", "summit", "sunset",
  "tablet", "tango", "tiger", "tomato", "topaz", "tulip", "tundra", "turtle",
]);
