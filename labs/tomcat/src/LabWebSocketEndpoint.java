package lab;

import javax.websocket.OnMessage;
import javax.websocket.server.ServerEndpoint;

/** Harmless echo endpoint used only to verify read-only runtime WebSocket discovery. */
@ServerEndpoint("/ws/{id}")
public final class LabWebSocketEndpoint {
    @OnMessage
    public String echo(String message) {
        return message;
    }
}
