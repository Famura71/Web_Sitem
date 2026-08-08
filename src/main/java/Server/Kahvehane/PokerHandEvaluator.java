package Server.Kahvehane;

import java.util.*;

public class PokerHandEvaluator {

    public static class PokerHand implements Comparable<PokerHand> {
        public enum HandRank {
            HIGH_CARD, ONE_PAIR, TWO_PAIR, THREE_OF_A_KIND, STRAIGHT, FLUSH, FULL_HOUSE, FOUR_OF_A_KIND, STRAIGHT_FLUSH
        }

        public final HandRank rank;
        public final int[] tieBreakers; // Evaluated ranks to break ties

        public PokerHand(HandRank rank, int[] tieBreakers) {
            this.rank = rank;
            this.tieBreakers = tieBreakers;
        }

        @Override
        public int compareTo(PokerHand o) {
            if (this.rank.ordinal() != o.rank.ordinal()) {
                return Integer.compare(this.rank.ordinal(), o.rank.ordinal());
            }
            for (int i = 0; i < Math.min(this.tieBreakers.length, o.tieBreakers.length); i++) {
                if (this.tieBreakers[i] != o.tieBreakers[i]) {
                    return Integer.compare(this.tieBreakers[i], o.tieBreakers[i]);
                }
            }
            return 0;
        }
    }

    private static class Card {
        int val; // 2 to 14 (Ace = 14)
        char suit; // H, D, C, S

        Card(String cardStr) {
            // Format: H_A, D_10, C_2, S_K
            String[] parts = cardStr.split("_");
            this.suit = parts[0].charAt(0);
            String valStr = parts[1];
            this.val = switch (valStr) {
                case "A" -> 14;
                case "K" -> 13;
                case "Q" -> 12;
                case "J" -> 11;
                default -> Integer.parseInt(valStr);
            };
        }
    }

    public static PokerHand evaluateBest5(List<String> cardStrings) {
        List<Card> cards = new ArrayList<>();
        for (String c : cardStrings) {
            cards.add(new Card(c));
        }

        // Generate combinations of 5 cards from the list (can be 5, 6, or 7 cards total)
        List<List<Card>> combinations = new ArrayList<>();
        generateCombinations(cards, new ArrayList<>(), 0, 5, combinations);

        PokerHand bestHand = null;
        for (List<Card> comb : combinations) {
            PokerHand hand = evaluate5CardHand(comb);
            if (bestHand == null || hand.compareTo(bestHand) > 0) {
                bestHand = hand;
            }
        }
        return bestHand;
    }

    private static void generateCombinations(List<Card> source, List<Card> current, int index, int k, List<List<Card>> results) {
        if (current.size() == k) {
            results.add(new ArrayList<>(current));
            return;
        }
        if (index >= source.size()) return;

        // Include
        current.add(source.get(index));
        generateCombinations(source, current, index + 1, k, results);
        current.remove(current.size() - 1);

        // Exclude
        generateCombinations(source, current, index + 1, k, results);
    }

    private static PokerHand evaluate5CardHand(List<Card> cards) {
        // Sort descending by value
        cards.sort((c1, c2) -> Integer.compare(c2.val, c1.val));

        boolean isFlush = cards.stream().allMatch(c -> c.suit == cards.get(0).suit);

        // Check straight
        boolean isStraight = true;
        for (int i = 0; i < 4; i++) {
            if (cards.get(i).val - cards.get(i + 1).val != 1) {
                isStraight = false;
                break;
            }
        }

        // Special case: Ace low straight (5, 4, 3, 2, A) -> Ace is val 14
        if (!isStraight && cards.get(0).val == 14 && cards.get(1).val == 5 &&
                cards.get(2).val == 4 && cards.get(3).val == 3 && cards.get(4).val == 2) {
            isStraight = true;
            // Re-order Ace to low (value becomes 1 for straight ranking)
            Card ace = cards.remove(0);
            ace.val = 1;
            cards.add(ace);
        }

        // Count values
        Map<Integer, Integer> counts = new HashMap<>();
        for (Card c : cards) {
            counts.put(c.val, counts.getOrDefault(c.val, 0) + 1);
        }

        List<Map.Entry<Integer, Integer>> countList = new ArrayList<>(counts.entrySet());
        // Sort by count descending, then value descending
        countList.sort((e1, e2) -> {
            if (!e1.getValue().equals(e2.getValue())) {
                return Integer.compare(e2.getValue(), e1.getValue());
            }
            return Integer.compare(e2.getKey(), e1.getKey());
        });

        int[] tieBreakers = new int[countList.size()];
        for (int i = 0; i < countList.size(); i++) {
            tieBreakers[i] = countList.get(i).getKey();
        }

        if (isFlush && isStraight) {
            return new PokerHand(PokerHand.HandRank.STRAIGHT_FLUSH, tieBreakers);
        }
        if (countList.get(0).getValue() == 4) {
            return new PokerHand(PokerHand.HandRank.FOUR_OF_A_KIND, tieBreakers);
        }
        if (countList.get(0).getValue() == 3 && countList.get(1).getValue() == 2) {
            return new PokerHand(PokerHand.HandRank.FULL_HOUSE, tieBreakers);
        }
        if (isFlush) {
            return new PokerHand(PokerHand.HandRank.FLUSH, tieBreakers);
        }
        if (isStraight) {
            return new PokerHand(PokerHand.HandRank.STRAIGHT, tieBreakers);
        }
        if (countList.get(0).getValue() == 3) {
            return new PokerHand(PokerHand.HandRank.THREE_OF_A_KIND, tieBreakers);
        }
        if (countList.get(0).getValue() == 2 && countList.get(1).getValue() == 2) {
            return new PokerHand(PokerHand.HandRank.TWO_PAIR, tieBreakers);
        }
        if (countList.get(0).getValue() == 2) {
            return new PokerHand(PokerHand.HandRank.ONE_PAIR, tieBreakers);
        }
        return new PokerHand(PokerHand.HandRank.HIGH_CARD, tieBreakers);
    }
}
