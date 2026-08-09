package Server.Kahvehane;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
public class KahvehaneWebSocketHandler extends TextWebSocketHandler {

    // Active rooms mapped by Room ID
    private final Map<String, GameRoom> rooms = new ConcurrentHashMap<>();
    // Map sessions to usernames
    private final Map<String, String> sessionUsernames = new ConcurrentHashMap<>();
    // Map sessions to room IDs
    private final Map<String, String> sessionRooms = new ConcurrentHashMap<>();
    // Map usernames to WebSocket sessions
    private final Map<String, WebSocketSession> userSessions = new ConcurrentHashMap<>();

    private final KahvehaneOyuncuRepository repository;

    public KahvehaneWebSocketHandler(KahvehaneOyuncuRepository repository) {
        this.repository = repository;
        // Prepopulate the 9 rooms (1 Blackjack, 2 Poker, 2 Pişti, 2 Batak, 2 Okey)
        rooms.put("blackjack-1", new GameRoom("blackjack-1", "blackjack", repository));
        
        for (int i = 1; i <= 2; i++) {
            rooms.put("poker-" + i, new GameRoom("poker-" + i, "poker", repository));
            rooms.put("pisti-" + i, new GameRoom("pisti-" + i, "pisti", repository));
            rooms.put("batak-" + i, new GameRoom("batak-" + i, "batak", repository));
            rooms.put("okey-" + i, new GameRoom("okey-" + i, "okey", repository));
        }
    }

    public Map<String, GameRoom> getRooms() {
        return rooms;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        // Connection opened, waiting for authentication/join action
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String payload = message.getPayload();
        if (payload.trim().isEmpty()) return;

        try {
            JSONObject json = new JSONObject(payload);
            String action = json.optString("action", "");

            switch (action) {
                case "join" -> handleJoin(session, json);
                case "game_action" -> handleGameAction(session, json);
                case "chat" -> handleChat(session, json);
                case "add_bot" -> handleAddBot(session, json);
                case "order_tea" -> handleOrderTea(session, json);
                default -> sendError(session, "Bilinmeyen aksiyon: " + action);
            }
        } catch (Exception e) {
            sendError(session, "Hata: " + e.getMessage());
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        String username = sessionUsernames.remove(session.getId());
        String roomId = sessionRooms.remove(session.getId());
        if (username != null) {
            userSessions.remove(username);
            if (roomId != null) {
                GameRoom room = rooms.get(roomId);
                if (room != null) {
                    room.removePlayer(session.getId());
                    broadcastRoomState(room);
                    // Keep rooms permanently on floor plan even when empty
                    // if (room.isEmpty()) { rooms.remove(roomId); }
                }
            }
        }
    }

    private void handleJoin(WebSocketSession session, JSONObject json) throws IOException {
        String username = json.optString("username", "").trim();
        String roomId = json.optString("roomId", "").trim();
        String gameType = json.optString("gameType", "blackjack").toLowerCase().trim();

        if (username.isEmpty() || roomId.isEmpty()) {
            sendError(session, "Kullanıcı adı ve Oda ID zorunludur!");
            return;
        }

        // Clean old session states if any
        sessionUsernames.put(session.getId(), username);
        sessionRooms.put(session.getId(), roomId);
        userSessions.put(username, session);

        GameRoom room = rooms.get(roomId);
        if (room == null) {
            sendError(session, "Masa bulunamadı: " + roomId);
            return;
        }

        if (room.getPlayers().size() >= 4) {
            sendError(session, "Masa dolu! (Maksimum 4 oyuncu)");
            return;
        }

        // Check if username is already taken in the room
        boolean usernameExists = room.getPlayers().stream()
                .anyMatch(p -> p.username().equals(username));

        if (usernameExists) {
            sendError(session, "Bu isimle zaten bir oyuncu masada!");
            return;
        }

        Optional<KahvehaneOyuncu> dbPlayerOpt = repository.findByKullaniciAdi(username);
        long balance = dbPlayerOpt.map(KahvehaneOyuncu::getBakiye).orElse(1000L);

        room.addPlayer(new RoomPlayer(session.getId(), username, balance, false));
        broadcastSystemChat(room, username + " masaya oturdu.");
        broadcastRoomState(room);
    }

    private void handleAddBot(WebSocketSession session, JSONObject json) throws IOException {
        String roomId = sessionRooms.get(session.getId());
        if (roomId == null) return;
        GameRoom room = rooms.get(roomId);
        if (room == null) return;

        // Fetch bots from DB
        List<KahvehaneOyuncu> dbBots = repository.findByIsBot(true);
        if (dbBots.isEmpty()) {
            sendError(session, "Veri tabanında hiç bot tanımlanmamış!");
            return;
        }

        // Find a bot not currently in the room
        KahvehaneOyuncu chosenBot = null;
        for (KahvehaneOyuncu bot : dbBots) {
            boolean alreadyInRoom = room.getPlayers().stream()
                    .anyMatch(p -> p.username().equals(bot.getKullaniciAdi()));
            if (!alreadyInRoom) {
                chosenBot = bot;
                break;
            }
        }

        if (chosenBot == null) {
            sendError(session, "Tüm botlar zaten masada!");
            return;
        }

        room.addPlayer(new RoomPlayer(UUID.randomUUID().toString(), chosenBot.getKullaniciAdi(), chosenBot.getBakiye(), true));
        broadcastSystemChat(room, chosenBot.getKullaniciAdi() + " masaya geldi.");
        broadcastRoomState(room);

        // Send a funny bot entrance chat
        sendBotChat(room, chosenBot.getKullaniciAdi(), getBotEntranceMessage(chosenBot.getKullaniciAdi()));
    }

    private void handleChat(WebSocketSession session, JSONObject json) throws IOException {
        String roomId = sessionRooms.get(session.getId());
        if (roomId == null) return;
        GameRoom room = rooms.get(roomId);
        if (room == null) return;

        String sender = sessionUsernames.get(session.getId());
        String msg = json.optString("message", "").trim();

        if (sender == null || msg.isEmpty()) return;

        broadcastChat(room, sender, msg);

        // Let bots react randomly to user chats
        triggerRandomBotReaction(room, msg);
    }

    private void handleOrderTea(WebSocketSession session, JSONObject json) throws IOException {
        String roomId = sessionRooms.get(session.getId());
        if (roomId == null) return;
        GameRoom room = rooms.get(roomId);
        if (room == null) return;

        String username = sessionUsernames.get(session.getId());
        if (username == null) return;

        String orderType = json.optString("item", "cay").toLowerCase();
        Optional<KahvehaneOyuncu> oyuncuOpt = repository.findByKullaniciAdi(username);
        if (oyuncuOpt.isEmpty()) return;

        KahvehaneOyuncu oyuncu = oyuncuOpt.get();
        long cost = switch (orderType) {
            case "cay" -> 10L;
            case "kahve" -> 30L;
            case "tost" -> 50L;
            default -> 0L;
        };

        if (oyuncu.getBakiye() < cost) {
            sendError(session, "Bakiye yetersiz, sipariş verilemedi!");
            return;
        }

        oyuncu.setBakiye(oyuncu.getBakiye() - cost);
        repository.save(oyuncu);

        // Update player info in the room list
        room.updatePlayerBalance(username, oyuncu.getBakiye());

        String itemTurkishName = switch (orderType) {
            case "cay" -> "tavşan kanı çay";
            case "kahve" -> "köpüklü kahve";
            case "tost" -> "karışık tost";
            default -> orderType;
        };

        broadcastSystemChat(room, username + " ocakçıdan bir " + itemTurkishName + " söyledi!");
        
        // Waiter reaction
        String waiterMsg = switch (orderType) {
            case "cay" -> "Ocakçı Remzi: Çayın taze geliyor yeğenim, afiyet olsun!";
            case "kahve" -> "Ocakçı Remzi: Kahveyi ocağa koydum, 40 yıl hatrımız olsun.";
            case "tost" -> "Ocakçı Remzi: Tost cızırdayarak pişiyor, sıcak sıcak yersin!";
            default -> "Ocakçı Remzi: Geliyor siparişin!";
        };
        sendBotChat(room, "Ocakçı Remzi", waiterMsg);

        // Broadcast order animation event
        JSONObject animationEvent = new JSONObject();
        animationEvent.put("type", "order_animation");
        animationEvent.put("username", username);
        animationEvent.put("item", orderType);
        broadcastMessage(room, animationEvent.toString());

        broadcastRoomState(room);
    }

    private void handleGameAction(WebSocketSession session, JSONObject json) throws IOException {
        String roomId = sessionRooms.get(session.getId());
        if (roomId == null) return;
        GameRoom room = rooms.get(roomId);
        if (room == null) return;

        String username = sessionUsernames.get(session.getId());
        if (username == null) return;

        JSONObject payload = json.optJSONObject("payload");
        if (payload == null) return;

        // Process game actions based on game type
        room.processGameAction(username, payload, this);
    }

    // Broadcast utilities
    public void broadcastRoomState(GameRoom room) {
        JSONObject response = new JSONObject();
        response.put("type", "room_state");
        response.put("roomId", room.getRoomId());
        response.put("gameType", room.getGameType());
        response.put("status", room.getStatus());
        response.put("turn", room.getCurrentTurnPlayerName());

        JSONArray playersArray = new JSONArray();
        for (RoomPlayer player : room.getPlayers()) {
            JSONObject pObj = new JSONObject();
            pObj.put("username", player.username());
            pObj.put("balance", player.balance());
            pObj.put("isBot", player.isBot());
            pObj.put("hand", new JSONArray(player.getHand()));
            pObj.put("score", player.getScore());
            pObj.put("status", player.getStatus());
            playersArray.put(pObj);
        }
        response.put("players", playersArray);

        // Game specific visual properties
        response.put("gameData", room.getGameDataJson());

        broadcastMessage(room, response.toString());
    }

    public void broadcastChat(GameRoom room, String sender, String message) {
        JSONObject response = new JSONObject();
        response.put("type", "chat");
        response.put("sender", sender);
        response.put("message", message);
        broadcastMessage(room, response.toString());
    }

    public void broadcastSystemChat(GameRoom room, String message) {
        broadcastChat(room, "Sistem", message);
    }

    public void sendBotChat(GameRoom room, String botName, String message) {
        broadcastChat(room, botName, message);
    }

    private void broadcastMessage(GameRoom room, String messageText) {
        TextMessage message = new TextMessage(messageText);
        for (RoomPlayer player : room.getPlayers()) {
            if (!player.isBot()) {
                WebSocketSession session = userSessions.get(player.username());
                if (session != null && session.isOpen()) {
                    try {
                        session.sendMessage(message);
                    } catch (IOException ignored) {
                    }
                }
            }
        }
    }

    private void sendError(WebSocketSession session, String errorMsg) throws IOException {
        JSONObject response = new JSONObject();
        response.put("type", "error");
        response.put("message", errorMsg);
        session.sendMessage(new TextMessage(response.toString()));
    }

    // Bot conversation utilities
    private String getBotEntranceMessage(String botName) {
        return switch (botName) {
            case "Nuri Dayı" -> "Selamunaleykum cemaat! Çayı olan masaya oturdum, dağıt bakalım.";
            case "Ahmet Dayı" -> "Hayırlı akşamlar beyler. Pokerde/okeyde blöf dinlemem haberiniz olsun.";
            case "Hüseyin Amca" -> "Ooo selamlar. Fazla vaktim yok ama bir iki el 21 atarım, hanım bekler.";
            case "Cemil Abi" -> "Selam beyler, bardağım boş kalmasın ona göre.";
            case "Ocakçı Remzi" -> "Masa dördüncü arıyordu, çay tepsimi bıraktım geldim.";
            default -> "Selam beyler, iyi oyunlar.";
        };
    }

    private void triggerRandomBotReaction(GameRoom room, String userMsg) {
        // 30% chance a bot replies to chat
        if (Math.random() > 0.3) return;

        List<RoomPlayer> botsInRoom = room.getPlayers().stream().filter(RoomPlayer::isBot).toList();
        if (botsInRoom.isEmpty()) return;

        RoomPlayer randomBot = botsInRoom.get(new Random().nextInt(botsInRoom.size()));
        String reply = getBotChatReply(randomBot.username(), userMsg);
        
        // Async dispatch after short delay for realism
        new Thread(() -> {
            try {
                Thread.sleep(1000 + new Random().nextInt(1500));
                sendBotChat(room, randomBot.username(), reply);
            } catch (InterruptedException ignored) {}
        }).start();
    }

    private String getBotChatReply(String botName, String userMsg) {
        userMsg = userMsg.toLowerCase();
        if (userMsg.contains("çay") || userMsg.contains("cay") || userMsg.contains("ocakçı")) {
            return switch (botName) {
                case "Nuri Dayı" -> "Bana da demli çay Remzi! Şekersiz olsun.";
                case "Ahmet Dayı" -> "Remzi, buraya iki çay çek biri bana biri masaya!";
                case "Hüseyin Amca" -> "Çay içelim çay, harareti alır.";
                default -> "Remzi yorulmuştur, ben kendim kalkıp alacağım şimdi.";
            };
        }
        if (userMsg.contains("kazandım") || userMsg.contains("yendim") || userMsg.contains("poker") || userMsg.contains("blöf")) {
            return switch (botName) {
                case "Nuri Dayı" -> "Şansın döner yeğenim, hele bir sonraki eli bekle.";
                case "Ahmet Dayı" -> "Balıkçı şansı o, ustalık değil.";
                case "Cemil Abi" -> "Blöf dedin de, geçen el benim karta blöf yapan sen miydin?";
                default -> "Tebrikler ama bu kahvehaneden kimse zengin kalkmadı daha.";
            };
        }
        // General replies
        return switch (botName) {
            case "Nuri Dayı" -> "Geçen yine okey oynuyorum Niyazi ile, çifte gittim bitti.";
            case "Ahmet Dayı" -> "Hadi hadi lafı bırak da eline odaklan.";
            case "Hüseyin Amca" -> "Gençlik işte, hep aceleleri var.";
            case "Cemil Abi" -> "Çaylar soğuyor beyler, oyunu hızlandırın.";
            default -> "Hadi bakalım, şansımız açık olsun.";
        };
    }
}
