package Server.Kahvehane;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.web.socket.TextMessage;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class GameRoom {
    private final String roomId;
    private final String gameType; // blackjack, poker, pisti, batak, okey
    private final List<RoomPlayer> players = new CopyOnWriteArrayList<>();
    private final KahvehaneOyuncuRepository repository;
    private String status = "LOBBY"; // LOBBY, PLAYING, ROUND_OVER
    private int turnIndex = 0;

    // Deck & community items
    private final List<String> deck = new ArrayList<>();
    private final List<String> discardPile = new ArrayList<>();
    private final List<String> communityCards = new ArrayList<>();

    // Okey tile bag & indicators
    private final List<String> tileBag = new ArrayList<>();
    private String okeyIndicator = "";
    private String okeyWildcard = "";

    // Poker specific state
    private long pot = 0;
    private long currentRoomBet = 0;
    private final long minBet = 20;
    private final Map<String, Long> playerBets = new HashMap<>();

    // Blackjack specific state
    private final List<String> dealerHand = new ArrayList<>();
    private int dealerScore = 0;
    private final long blackjackBet = 50; // Default bet

    // Batak specific state
    private String koz = ""; // Trump suit
    private int contractBid = 0;
    private String contractWinner = "";
    private final List<String> trickCards = new ArrayList<>(); // Cards currently played on the table

    public GameRoom(String roomId, String gameType, KahvehaneOyuncuRepository repository) {
        this.roomId = roomId;
        this.gameType = gameType;
        this.repository = repository;
    }

    public String getRoomId() { return roomId; }
    public String getGameType() { return gameType; }
    public String getStatus() { return status; }
    public List<RoomPlayer> getPlayers() { return players; }

    public synchronized void addPlayer(RoomPlayer player) {
        players.add(player);
    }

    public synchronized void removePlayer(String sessionId) {
        players.removeIf(p -> p.sessionId().equals(sessionId));
    }

    public boolean isEmpty() {
        return players.isEmpty();
    }

    public synchronized void updatePlayerBalance(String username, long newBalance) {
        for (RoomPlayer p : players) {
            if (p.username().equals(username)) {
                p.setBalance(newBalance);
                break;
            }
        }
    }

    public String getCurrentTurnPlayerName() {
        if (players.isEmpty() || !"PLAYING".equals(status)) return "";
        return players.get(turnIndex % players.size()).username();
    }

    // Process player actions
    public synchronized void processGameAction(String username, JSONObject payload, KahvehaneWebSocketHandler handler) {
        String actionType = payload.optString("type", "");

        if ("start".equals(actionType)) {
            startGame(handler);
            return;
        }

        if (!"PLAYING".equals(status)) {
            return;
        }

        // Validate turn (except for Blackjack where betting is parallel, or multi-player setups)
        String currentTurnName = getCurrentTurnPlayerName();
        if (!gameType.equals("blackjack") && !currentTurnName.equals(username)) {
            return; // Not your turn
        }

        switch (gameType) {
            case "blackjack" -> handleBlackjackAction(username, payload, handler);
            case "poker" -> handlePokerAction(username, payload, handler);
            case "pisti" -> handlePistiAction(username, payload, handler);
            case "batak" -> handleBatakAction(username, payload, handler);
            case "okey" -> handleOkeyAction(username, payload, handler);
        }
    }

    // Initialize deck of cards
    private void initCardDeck() {
        deck.clear();
        String[] suits = {"H", "D", "C", "S"}; // Hearts, Diamonds, Clubs, Spades
        String[] ranks = {"2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"};
        for (String s : suits) {
            for (String r : ranks) {
                deck.add(s + "_" + r);
            }
        }
        Collections.shuffle(deck);
    }

    // Initialize 101 Okey Tiles
    private void initOkeyTiles() {
        tileBag.clear();
        String[] colors = {"R", "B", "Y", "K"}; // Red, Blue, Yellow, Black
        for (String c : colors) {
            for (int i = 1; i <= 13; i++) {
                tileBag.add(c + "_" + i);
                tileBag.add(c + "_" + i); // 2 of each tile
            }
        }
        tileBag.add("F_OKEY"); // 2 Fake Okeys
        tileBag.add("F_OKEY");
        Collections.shuffle(tileBag);
    }

    // Start game trigger
    private void startGame(KahvehaneWebSocketHandler handler) {
        if (players.size() < 1) return;

        status = "PLAYING";
        turnIndex = 0;
        communityCards.clear();
        discardPile.clear();
        playerBets.clear();
        pot = 0;

        for (RoomPlayer p : players) {
            p.clearHand();
            p.setStatus("PLAYING");
        }

        switch (gameType) {
            case "blackjack" -> startBlackjack(handler);
            case "poker" -> startPoker(handler);
            case "pisti" -> startPisti(handler);
            case "batak" -> startBatak(handler);
            case "okey" -> startOkey(handler);
        }
    }

    // ==========================================
    // 21 (BLACKJACK) LOGIC
    // ==========================================
    private void startBlackjack(KahvehaneWebSocketHandler handler) {
        initCardDeck();
        dealerHand.clear();
        dealerScore = 0;

        // Auto-deduct bet (50 TL)
        for (RoomPlayer p : players) {
            p.setStatus("PLAYING");
            p.setBalance(Math.max(0, p.balance() - blackjackBet));
            // Update balance in DB
            Optional<KahvehaneOyuncu> dbPlayerOpt = repository.findByKullaniciAdi(p.username());
            if (dbPlayerOpt.isPresent()) {
                KahvehaneOyuncu dbPlayer = dbPlayerOpt.get();
                dbPlayer.setBakiye(p.balance());
                repository.save(dbPlayer);
            }
            // Deal 2 cards
            p.addCard(drawCard());
            p.addCard(drawCard());
            p.setScore(calculateBlackjackScore(p.getHand()));
            if (p.getScore() == 21) {
                p.setStatus("STAND");
            }
        }

        // Dealer cards
        dealerHand.add(drawCard());
        dealerHand.add(drawCard()); // Second card is face-down
        dealerScore = calculateBlackjackScore(dealerHand);

        handler.broadcastSystemChat(this, "El başladı. Bahisler (50 TL) alındı. Kartlar dağıtıldı.");
        handler.broadcastRoomState(this);

        // Check if round is already finished (all players blackjack/stand)
        checkBlackjackRoundEnd(handler);
    }

    private void handleBlackjackAction(String username, JSONObject payload, KahvehaneWebSocketHandler handler) {
        String subAction = payload.optString("action", "");
        RoomPlayer p = getPlayerByUsername(username);
        if (p == null || !p.getStatus().equals("PLAYING")) return;

        if ("hit".equals(subAction)) {
            p.addCard(drawCard());
            int score = calculateBlackjackScore(p.getHand());
            p.setScore(score);
            if (score > 21) {
                p.setStatus("BUST");
                handler.broadcastSystemChat(this, p.username() + " 21'i aştı (Bust)!");
            }
            handler.broadcastRoomState(this);
            checkBlackjackRoundEnd(handler);
        } else if ("stand".equals(subAction)) {
            p.setStatus("STAND");
            handler.broadcastSystemChat(this, p.username() + " Kaldı (Stand).");
            handler.broadcastRoomState(this);
            checkBlackjackRoundEnd(handler);
        }
    }

    private void checkBlackjackRoundEnd(KahvehaneWebSocketHandler handler) {
        boolean allFinished = true;
        for (RoomPlayer p : players) {
            if (p.getStatus().equals("PLAYING")) {
                // If it's a bot, let it make a decision automatically
                if (p.isBot()) {
                    playBlackjackBotTurn(p, handler);
                } else {
                    allFinished = false;
                }
            }
        }

        if (allFinished) {
            resolveBlackjackRound(handler);
        }
    }

    private void playBlackjackBotTurn(RoomPlayer bot, KahvehaneWebSocketHandler handler) {
        // Bot strategy: hit if score < 17, else stand
        while (bot.getStatus().equals("PLAYING")) {
            int score = calculateBlackjackScore(bot.getHand());
            if (score < 17) {
                bot.addCard(drawCard());
                bot.setScore(calculateBlackjackScore(bot.getHand()));
                if (bot.getScore() > 21) {
                    bot.setStatus("BUST");
                    handler.broadcastSystemChat(this, bot.username() + " (Bot) 21'i aştı!");
                }
            } else {
                bot.setStatus("STAND");
                handler.broadcastSystemChat(this, bot.username() + " (Bot) Kaldı.");
            }
        }
    }

    private void resolveBlackjackRound(KahvehaneWebSocketHandler handler) {
        status = "ROUND_OVER";

        // Dealer plays if anyone is still alive (STAND status)
        boolean anyoneAlive = players.stream().anyMatch(p -> p.getStatus().equals("STAND"));
        if (anyoneAlive) {
            while (dealerScore < 17) {
                dealerHand.add(drawCard());
                dealerScore = calculateBlackjackScore(dealerHand);
            }
        }

        // Compare and payout
        for (RoomPlayer p : players) {
            Optional<KahvehaneOyuncu> dbPlayerOpt = repository.findByKullaniciAdi(p.username());
            if (dbPlayerOpt.isEmpty()) continue;
            KahvehaneOyuncu dbPlayer = dbPlayerOpt.get();
            dbPlayer.setGamesPlayed(dbPlayer.getGamesPlayed() + 1);

            if (p.getStatus().equals("BUST")) {
                handler.broadcastSystemChat(this, p.username() + " kasaya kaybetti.");
            } else {
                // Player stands
                if (dealerScore > 21) {
                    // Dealer bust, player wins
                    long winnings = blackjackBet * 2;
                    p.setBalance(p.balance() + winnings);
                    dbPlayer.setBakiye(p.balance());
                    dbPlayer.setGamesWon(dbPlayer.getGamesWon() + 1);
                    handler.broadcastSystemChat(this, "Kasa battı! " + p.username() + " " + winnings + " TL kazandı.");
                } else if (p.getScore() > dealerScore) {
                    // Player wins
                    long winnings = blackjackBet * 2;
                    p.setBalance(p.balance() + winnings);
                    dbPlayer.setBakiye(p.balance());
                    dbPlayer.setGamesWon(dbPlayer.getGamesWon() + 1);
                    handler.broadcastSystemChat(this, p.username() + " kasayı yendi! " + winnings + " TL kazandı.");
                } else if (p.getScore() == dealerScore) {
                    // Tie (Push) - refund bet
                    p.setBalance(p.balance() + blackjackBet);
                    dbPlayer.setBakiye(p.balance());
                    handler.broadcastSystemChat(this, p.username() + " ile Kasa berabere kaldı. Bahis iade.");
                } else {
                    // Loss
                    handler.broadcastSystemChat(this, p.username() + " kasaya kaybetti (" + p.getScore() + " vs " + dealerScore + ").");
                }
            }
            repository.save(dbPlayer);
        }

        handler.broadcastRoomState(this);
    }

    private int calculateBlackjackScore(List<String> hand) {
        int score = 0;
        int aces = 0;
        for (String c : hand) {
            String rank = c.split("_")[1];
            if (rank.equals("A")) {
                aces++;
                score += 11;
            } else if (rank.equals("K") || rank.equals("Q") || rank.equals("J")) {
                score += 10;
            } else {
                score += Integer.parseInt(rank);
            }
        }
        while (score > 21 && aces > 0) {
            score -= 10;
            aces--;
        }
        return score;
    }

    // ==========================================
    // TEXAS HOLD'EM POKER LOGIC
    // ==========================================
    private void startPoker(KahvehaneWebSocketHandler handler) {
        initCardDeck();
        pot = 0;
        currentRoomBet = minBet;

        // Auto-blind blinds (e.g. SB = 10, BB = 20)
        long smallBlind = minBet / 2;
        long bigBlind = minBet;

        if (players.size() >= 2) {
            RoomPlayer sbPlayer = players.get(0);
            RoomPlayer bbPlayer = players.get(1);

            sbPlayer.setBalance(Math.max(0, sbPlayer.balance() - smallBlind));
            bbPlayer.setBalance(Math.max(0, bbPlayer.balance() - bigBlind));
            playerBets.put(sbPlayer.username(), smallBlind);
            playerBets.put(bbPlayer.username(), bigBlind);
            pot += (smallBlind + bigBlind);

            // Update in DB
            for (RoomPlayer p : List.of(sbPlayer, bbPlayer)) {
                repository.findByKullaniciAdi(p.username()).ifPresent(db -> {
                    db.setBakiye(p.balance());
                    repository.save(db);
                });
            }
        }

        // Deal 2 pocket cards
        for (RoomPlayer p : players) {
            p.addCard(drawCard());
            p.addCard(drawCard());
            p.setStatus("PLAYING");
        }

        turnIndex = players.size() >= 3 ? 2 : 0; // Set turn index to next player after big blind
        handler.broadcastSystemChat(this, "Poker eli başladı. Kartlar dağıtıldı. Kör bahisler alındı.");
        handler.broadcastRoomState(this);
    }

    private void handlePokerAction(String username, JSONObject payload, KahvehaneWebSocketHandler handler) {
        String pokerAction = payload.optString("action", ""); // fold, check, call, raise
        long raiseAmount = payload.optLong("amount", 0);
        RoomPlayer p = getPlayerByUsername(username);
        if (p == null || !p.getStatus().equals("PLAYING")) return;

        long currentBetOfPlayer = playerBets.getOrDefault(username, 0L);
        long callAmountNeeded = currentRoomBet - currentBetOfPlayer;

        switch (pokerAction) {
            case "fold" -> {
                p.setStatus("FOLDED");
                handler.broadcastSystemChat(this, username + " pas geçti (Fold).");
            }
            case "check" -> {
                if (callAmountNeeded > 0) {
                    sendErrorDirect(p, handler, "Check yapamazsınız, görmeniz gereken miktar var!");
                    return;
                }
                handler.broadcastSystemChat(this, username + " kontrol etti (Check).");
            }
            case "call" -> {
                if (p.balance() < callAmountNeeded) {
                    // All-in scenario
                    callAmountNeeded = p.balance();
                }
                p.setBalance(p.balance() - callAmountNeeded);
                playerBets.put(username, currentBetOfPlayer + callAmountNeeded);
                pot += callAmountNeeded;
                handler.broadcastSystemChat(this, username + " gördü (Call: " + callAmountNeeded + " TL).");
            }
            case "raise" -> {
                long totalNewBet = currentRoomBet + raiseAmount;
                long totalAddRequired = totalNewBet - currentBetOfPlayer;
                if (p.balance() < totalAddRequired) {
                    sendErrorDirect(p, handler, "Bakiye yetersiz, bu miktarda artıramazsınız!");
                    return;
                }
                p.setBalance(p.balance() - totalAddRequired);
                playerBets.put(username, totalNewBet);
                currentRoomBet = totalNewBet;
                pot += totalAddRequired;
                handler.broadcastSystemChat(this, username + " artırdı (Raise: +" + raiseAmount + " TL, Toplam Bet: " + totalNewBet + ").");
            }
        }

        // Save new balance to DB
        repository.findByKullaniciAdi(username).ifPresent(db -> {
            db.setBakiye(p.balance());
            repository.save(db);
        });

        // Next Turn
        moveToNextPokerTurn(handler);
    }

    private void moveToNextPokerTurn(KahvehaneWebSocketHandler handler) {
        // Count active players (not folded, not all-in)
        long activeCount = players.stream().filter(p -> p.getStatus().equals("PLAYING")).count();
        if (activeCount <= 1) {
            resolvePokerShowdown(handler);
            return;
        }

        // Check if betting round complete: All active players have bet equal to currentRoomBet
        boolean bettingRoundComplete = true;
        for (RoomPlayer p : players) {
            if (p.getStatus().equals("PLAYING")) {
                long pBet = playerBets.getOrDefault(p.username(), 0L);
                if (pBet < currentRoomBet) {
                    bettingRoundComplete = false;
                    break;
                }
            }
        }

        if (bettingRoundComplete) {
            // Reset player bets for next round
            playerBets.clear();
            currentRoomBet = 0;

            // Transition to next street
            if (communityCards.isEmpty()) {
                // Deal Flop (3 cards)
                communityCards.add(drawCard());
                communityCards.add(drawCard());
                communityCards.add(drawCard());
                handler.broadcastSystemChat(this, "Flop açıldı: " + String.join(", ", communityCards));
            } else if (communityCards.size() == 3) {
                // Deal Turn (1 card)
                communityCards.add(drawCard());
                handler.broadcastSystemChat(this, "Turn açıldı: " + communityCards.get(3));
            } else if (communityCards.size() == 4) {
                // Deal River (1 card)
                communityCards.add(drawCard());
                handler.broadcastSystemChat(this, "River açıldı: " + communityCards.get(4));
            } else {
                // Showdown!
                resolvePokerShowdown(handler);
                return;
            }
        }

        // Find next playing player
        do {
            turnIndex++;
        } while (!players.get(turnIndex % players.size()).getStatus().equals("PLAYING"));

        // If bot's turn, auto play
        RoomPlayer currentP = players.get(turnIndex % players.size());
        if (currentP.isBot()) {
            playPokerBotTurn(currentP, handler);
        } else {
            handler.broadcastRoomState(this);
        }
    }
    private void playPokerBotTurn(final RoomPlayer bot, final KahvehaneWebSocketHandler handler) {
        // Simple Bot logic: call if needed, check if possible, fold if bet too high
        final long currentBetOfBot = playerBets.getOrDefault(bot.username(), 0L);
        final long callNeeded = currentRoomBet - currentBetOfBot;

        new Thread(() -> {
            try {
                Thread.sleep(1000 + new Random().nextInt(1000));
                synchronized (this) {
                    if (callNeeded == 0) {
                        // Check
                        handler.broadcastSystemChat(this, bot.username() + " (Bot) kontrol etti (Check).");
                    } else if (callNeeded <= 100 && bot.balance() >= callNeeded) {
                        // Call
                        bot.setBalance(bot.balance() - callNeeded);
                        playerBets.put(bot.username(), currentBetOfBot + callNeeded);
                        pot += callNeeded;
                        handler.broadcastSystemChat(this, bot.username() + " (Bot) gördü (Call).");
                    } else {
                        // Fold
                        bot.setStatus("FOLDED");
                        handler.broadcastSystemChat(this, bot.username() + " (Bot) pas geçti (Fold).");
                    }
                    
                    // Save
                    repository.findByKullaniciAdi(bot.username()).ifPresent(db -> {
                        db.setBakiye(bot.balance());
                        repository.save(db);
                    });

                    moveToNextPokerTurn(handler);
                }
            } catch (InterruptedException ignored) {}
        }).start();
    }

    private void resolvePokerShowdown(KahvehaneWebSocketHandler handler) {
        status = "ROUND_OVER";

        // Find remaining active players
        List<RoomPlayer> activePlayers = players.stream()
                .filter(p -> p.getStatus().equals("PLAYING"))
                .toList();

        if (activePlayers.isEmpty()) {
            handler.broadcastSystemChat(this, "Masada kimse kalmadı! El berabere bitti.");
            handler.broadcastRoomState(this);
            return;
        }

        if (activePlayers.size() == 1) {
            // Only 1 player left (others folded)
            RoomPlayer winner = activePlayers.get(0);
            winner.setBalance(winner.balance() + pot);
            repository.findByKullaniciAdi(winner.username()).ifPresent(db -> {
                db.setBakiye(winner.balance());
                db.setGamesPlayed(db.getGamesPlayed() + 1);
                db.setGamesWon(db.getGamesWon() + 1);
                repository.save(db);
            });
            handler.broadcastSystemChat(this, winner.username() + " eli kazandı! Pot: " + pot + " TL.");
            handler.broadcastRoomState(this);
            return;
        }

        // Multiple players: evaluate best 5 cards out of pocket + community
        RoomPlayer absoluteWinner = null;
        PokerHandEvaluator.PokerHand winningHand = null;

        for (RoomPlayer p : activePlayers) {
            List<String> combined = new ArrayList<>(p.getHand());
            combined.addAll(communityCards);
            PokerHandEvaluator.PokerHand hand = PokerHandEvaluator.evaluateBest5(combined);
            p.setScore(hand.rank.ordinal()); // Save rank index as score for displaying in UI
            if (winningHand == null || hand.compareTo(winningHand) > 0) {
                winningHand = hand;
                absoluteWinner = p;
            }
        }

        if (absoluteWinner != null) {
            absoluteWinner.setBalance(absoluteWinner.balance() + pot);
            PokerHandEvaluator.PokerHand.HandRank r = winningHand.rank;
            String handTurkish = translatePokerHand(r);

            handler.broadcastSystemChat(this, absoluteWinner.username() + " eli kazandı! El: " + handTurkish + ". Pot: " + pot + " TL.");

            final RoomPlayer finalWinner = absoluteWinner;

            // Update stats
            for (RoomPlayer p : players) {
                repository.findByKullaniciAdi(p.username()).ifPresent(db -> {
                    db.setGamesPlayed(db.getGamesPlayed() + 1);
                    if (p.username().equals(finalWinner.username())) {
                        db.setBakiye(p.balance());
                        db.setGamesWon(db.getGamesWon() + 1);
                    }
                    repository.save(db);
                });
            }
        }

        handler.broadcastRoomState(this);
    }

    private String translatePokerHand(PokerHandEvaluator.PokerHand.HandRank rank) {
        return switch (rank) {
            case STRAIGHT_FLUSH -> "Sıralı Renk (Straight Flush)";
            case FOUR_OF_A_KIND -> "Kare (Four of a Kind)";
            case FULL_HOUSE -> "Ful (Full House)";
            case FLUSH -> "Renk (Flush)";
            case STRAIGHT -> "Kent (Straight)";
            case THREE_OF_A_KIND -> "Üçlü (Three of a Kind)";
            case TWO_PAIR -> "Döper (Two Pair)";
            case ONE_PAIR -> "Per (One Pair)";
            default -> "Yüksek Kart (High Card)";
        };
    }

    // ==========================================
    // PİŞTİ LOGIC
    // ==========================================
    private void startPisti(KahvehaneWebSocketHandler handler) {
        initCardDeck();
        communityCards.clear();

        // Deal 4 cards to players
        for (RoomPlayer p : players) {
            p.setStatus("PLAYING");
            for (int i = 0; i < 4; i++) p.addCard(drawCard());
        }

        // Deal 4 cards to middle (3 face down, 1 face up)
        for (int i = 0; i < 4; i++) {
            communityCards.add(drawCard());
        }

        handler.broadcastSystemChat(this, "Pişti eli başladı. Yere 4 kart açıldı.");
        handler.broadcastRoomState(this);
    }

    private void handlePistiAction(String username, JSONObject payload, KahvehaneWebSocketHandler handler) {
        String card = payload.optString("card", ""); // e.g. "H_A"
        RoomPlayer p = getPlayerByUsername(username);
        if (p == null || card.isEmpty()) return;

        // Verify player has card in hand
        if (!p.getHand().remove(card)) {
            return;
        }

        boolean captured = false;
        boolean wasPisti = false;

        if (!communityCards.isEmpty()) {
            String topCard = communityCards.get(communityCards.size() - 1);
            String topRank = topCard.split("_")[1];
            String playedRank = card.split("_")[1];

            // Capture if played rank equals top card rank, or if played card is a Jack
            if (playedRank.equals(topRank) || playedRank.equals("J")) {
                captured = true;
                // Check if it was a Pişti
                if (communityCards.size() == 1) {
                    wasPisti = true;
                    int points = playedRank.equals("J") ? 10 : 5;
                    p.setScore(p.getScore() + points);
                    handler.broadcastSystemChat(this, username + " PİŞTİ YAPTI! (+" + points + " Puan)");
                } else {
                    p.setScore(p.getScore() + 1); // Increment capture count/score
                    handler.broadcastSystemChat(this, username + " yerdeki kartları aldı.");
                }
            }
        }

        if (captured) {
            communityCards.clear();
        } else {
            communityCards.add(card);
        }

        // Switch turn
        turnIndex = (turnIndex + 1) % players.size();

        // Check if hand dealing is required
        boolean handsEmpty = players.stream().allMatch(pl -> pl.getHand().isEmpty());
        if (handsEmpty) {
            if (!deck.isEmpty()) {
                // Deal next 4 cards
                for (RoomPlayer pl : players) {
                    for (int i = 0; i < 4; i++) pl.addCard(drawCard());
                }
                handler.broadcastSystemChat(this, "Yeni kartlar dağıtıldı.");
            } else {
                // Game Over
                status = "ROUND_OVER";
                // Declare winner based on score
                RoomPlayer winner = players.get(0);
                for (RoomPlayer pl : players) {
                    if (pl.getScore() > winner.getScore()) {
                        winner = pl;
                    }
                }
                handler.broadcastSystemChat(this, "Oyun bitti! En çok puanı toplayan " + winner.username() + " kazandı.");
                
                // Add virtual money (e.g. 200 TL)
                final String winnerName = winner.username();
                for (RoomPlayer pl : players) {
                    repository.findByKullaniciAdi(pl.username()).ifPresent(db -> {
                        db.setGamesPlayed(db.getGamesPlayed() + 1);
                        if (pl.username().equals(winnerName)) {
                            db.setBakiye(db.getBakiye() + 200L);
                            pl.setBalance(db.getBakiye());
                            db.setGamesWon(db.getGamesWon() + 1);
                        }
                        repository.save(db);
                    });
                }
            }
        }

        // Bot turn auto trigger
        RoomPlayer nextP = players.get(turnIndex);
        if (nextP.isBot() && !"ROUND_OVER".equals(status)) {
            playPistiBotTurn(nextP, handler);
        } else {
            handler.broadcastRoomState(this);
        }
    }

    private void playPistiBotTurn(final RoomPlayer bot, final KahvehaneWebSocketHandler handler) {
        new Thread(() -> {
            try {
                Thread.sleep(1200 + new Random().nextInt(800));
                synchronized (this) {
                    if (bot.getHand().isEmpty()) return;
                    // Simpler bot AI: throw matching rank card if possible, else random card
                    String cardToThrow = bot.getHand().get(0);
                    if (!communityCards.isEmpty()) {
                        String topCard = communityCards.get(communityCards.size() - 1);
                        String topRank = topCard.split("_")[1];
                        for (String c : bot.getHand()) {
                            if (c.split("_")[1].equals(topRank)) {
                                cardToThrow = c;
                                break;
                            }
                        }
                    }

                    JSONObject botAction = new JSONObject();
                    botAction.put("card", cardToThrow);
                    handlePistiAction(bot.username(), botAction, handler);
                }
            } catch (InterruptedException ignored) {}
        }).start();
    }

    // ==========================================
    // BATAK / 101 OKEY / SUGGESTED GAMES SKELETON
    // ==========================================
    private void startBatak(KahvehaneWebSocketHandler handler) {
        initCardDeck();
        koz = "S"; // Spades (Koz Maça) is default
        contractBid = 4; // Min bid is 4
        contractWinner = players.get(0).username();

        // Deal 13 cards to players (assuming 4 players/bots)
        while (players.size() < 4) {
            // Auto add bots to fill the batak table
            List<KahvehaneOyuncu> dbBots = repository.findByIsBot(true);
            String botName = "Bot " + (players.size() + 1);
            if (!dbBots.isEmpty()) {
                botName = dbBots.get(new Random().nextInt(dbBots.size())).getKullaniciAdi();
            }
            addPlayer(new RoomPlayer(UUID.randomUUID().toString(), botName, 1000L, true));
        }

        for (RoomPlayer p : players) {
            p.setStatus("PLAYING");
            for (int i = 0; i < 13; i++) p.addCard(drawCard());
        }

        handler.broadcastSystemChat(this, "Batak başladı! Koz: Maça. İhale Nuri Dayı'da kaldı.");
        handler.broadcastRoomState(this);
    }

    private void handleBatakAction(String username, JSONObject payload, KahvehaneWebSocketHandler handler) {
        // Batak simplified trick play
        String card = payload.optString("card", "");
        RoomPlayer p = getPlayerByUsername(username);
        if (p == null || card.isEmpty()) return;

        p.getHand().remove(card);
        trickCards.add(card + " (" + username + ")");

        if (trickCards.size() == 4) {
            // Trick over, announce winner (for simplicity, last player wins the trick or random)
            RoomPlayer trickWinner = players.get(new Random().nextInt(4));
            trickWinner.setScore(trickWinner.getScore() + 1);
            handler.broadcastSystemChat(this, "Eli alan oyuncu: " + trickWinner.username());
            trickCards.clear();
        }

        turnIndex = (turnIndex + 1) % players.size();

        // Check if hand over
        boolean handOver = players.stream().allMatch(pl -> pl.getHand().isEmpty());
        if (handOver) {
            status = "ROUND_OVER";
            RoomPlayer gameWinner = players.get(0);
            for (RoomPlayer pl : players) {
                if (pl.getScore() > gameWinner.getScore()) gameWinner = pl;
            }
            handler.broadcastSystemChat(this, "Batak bitti! En çok eli alan kazandı: " + gameWinner.username());
        }

        final RoomPlayer nextP = players.get(turnIndex);
        if (nextP.isBot() && !"ROUND_OVER".equals(status)) {
            new Thread(() -> {
                try {
                    Thread.sleep(1500);
                    synchronized (this) {
                        if (nextP.getHand().isEmpty()) return;
                        JSONObject botAction = new JSONObject();
                        botAction.put("card", nextP.getHand().get(0));
                        handleBatakAction(nextP.username(), botAction, handler);
                    }
                } catch (Exception ignored) {}
            }).start();
        } else {
            handler.broadcastRoomState(this);
        }
    }

    private void startOkey(KahvehaneWebSocketHandler handler) {
        initOkeyTiles();
        okeyIndicator = tileBag.remove(0); // Top indicator
        // Set wildcard (Indicator + 1)
        okeyWildcard = calculateOkeyWildcard(okeyIndicator);

        // Deal 21 tiles to players (22 to starting player)
        for (int i = 0; i < players.size(); i++) {
            RoomPlayer p = players.get(i);
            int tilesCount = (i == 0) ? 22 : 21;
            for (int t = 0; t < tilesCount; t++) {
                p.addCard(tileBag.remove(0)); // We store okey tiles in the 'hand' list
            }
            p.setStatus("PLAYING");
        }

        handler.broadcastSystemChat(this, "101 Okey oyunu başladı! Gösterge: " + okeyIndicator);
        handler.broadcastRoomState(this);
    }

    private void handleOkeyAction(String username, JSONObject payload, KahvehaneWebSocketHandler handler) {
        String subAction = payload.optString("action", ""); // draw, discard, open
        RoomPlayer p = getPlayerByUsername(username);
        if (p == null) return;

        if ("draw".equals(subAction)) {
            if (!tileBag.isEmpty()) {
                String tile = tileBag.remove(0);
                p.addCard(tile);
                handler.broadcastSystemChat(this, username + " taş çekti.");
            }
        } else if ("discard".equals(subAction)) {
            String tile = payload.optString("tile", "");
            if (p.getHand().remove(tile)) {
                discardPile.add(tile);
                handler.broadcastSystemChat(this, username + " yandaki oyuncuya " + tile + " attı.");
                turnIndex = (turnIndex + 1) % players.size();
            }
        }

        // Check if bot's turn
        final RoomPlayer nextP = players.get(turnIndex);
        if (nextP.isBot() && !"ROUND_OVER".equals(status)) {
            new Thread(() -> {
                try {
                    Thread.sleep(1500);
                    synchronized (this) {
                        // Bot draws, then discards a random tile
                        if (!tileBag.isEmpty()) {
                            nextP.addCard(tileBag.remove(0));
                        }
                        String botDiscard = nextP.getHand().remove(0);
                        discardPile.add(botDiscard);
                        handler.broadcastSystemChat(this, nextP.username() + " (Bot) taş attı.");
                        turnIndex = (turnIndex + 1) % players.size();
                        handler.broadcastRoomState(this);
                    }
                } catch (Exception ignored) {}
            }).start();
        } else {
            handler.broadcastRoomState(this);
        }
    }

    private String calculateOkeyWildcard(String indicator) {
        if (indicator.equals("F_OKEY")) return "R_1";
        String[] parts = indicator.split("_");
        String color = parts[0];
        int num = Integer.parseInt(parts[1]);
        int nextNum = (num == 13) ? 1 : num + 1;
        return color + "_" + nextNum;
    }

    // Helper functions
    private RoomPlayer getPlayerByUsername(String username) {
        for (RoomPlayer p : players) {
            if (p.username().equals(username)) return p;
        }
        return null;
    }

    private String drawCard() {
        if (deck.isEmpty()) initCardDeck();
        return deck.remove(0);
    }

    private void sendErrorDirect(RoomPlayer player, KahvehaneWebSocketHandler handler, String errorMsg) {
        // Send directly to the player's web socket if open
        if (player.isBot()) return;
        JSONObject response = new JSONObject();
        response.put("type", "error");
        response.put("message", errorMsg);
        try {
            handler.handleTextMessage(null, new TextMessage(response.toString()));
        } catch (Exception ignored) {}
    }

    public JSONObject getGameDataJson() {
        JSONObject data = new JSONObject();
        data.put("deckSize", deck.size());
        data.put("communityCards", new JSONArray(communityCards));
        data.put("discardPile", new JSONArray(discardPile));
        data.put("pot", pot);
        data.put("currentRoomBet", currentRoomBet);
        data.put("okeyIndicator", okeyIndicator);
        data.put("okeyWildcard", okeyWildcard);
        data.put("koz", koz);
        data.put("dealerHand", new JSONArray(dealerHand));
        data.put("dealerScore", dealerScore);
        data.put("trickCards", new JSONArray(trickCards));
        return data;
    }
}
