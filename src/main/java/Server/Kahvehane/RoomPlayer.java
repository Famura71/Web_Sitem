package Server.Kahvehane;

import java.util.ArrayList;
import java.util.List;

public class RoomPlayer {
    private final String sessionId;
    private final String username;
    private Long balance;
    private final Boolean isBot;
    private List<String> hand = new ArrayList<>();
    private int score = 0;
    private String status = "WAITING"; // WAITING, PLAYING, FOLDED, STAND, BUST, etc.

    public RoomPlayer(String sessionId, String username, Long balance, Boolean isBot) {
        this.sessionId = sessionId;
        this.username = username;
        this.balance = balance;
        this.isBot = isBot;
    }

    public String sessionId() {
        return sessionId;
    }

    public String username() {
        return username;
    }

    public Long balance() {
        return balance;
    }

    public void setBalance(Long balance) {
        this.balance = balance;
    }

    public Boolean isBot() {
        return isBot;
    }

    public List<String> getHand() {
        return hand;
    }

    public void setHand(List<String> hand) {
        this.hand = hand;
    }

    public void addCard(String card) {
        this.hand.add(card);
    }

    public void clearHand() {
        this.hand.clear();
        this.score = 0;
        this.status = "WAITING";
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
