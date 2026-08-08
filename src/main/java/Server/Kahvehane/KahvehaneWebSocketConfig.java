package Server.Kahvehane;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class KahvehaneWebSocketConfig implements WebSocketConfigurer {

    private final KahvehaneWebSocketHandler webSocketHandler;

    public KahvehaneWebSocketConfig(KahvehaneWebSocketHandler webSocketHandler) {
        this.webSocketHandler = webSocketHandler;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(webSocketHandler, "/ws/hermes")
                .setAllowedOrigins("*");
    }
}
