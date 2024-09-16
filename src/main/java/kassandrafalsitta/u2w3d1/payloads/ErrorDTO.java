package kassandrafalsitta.u2w3d1.payloads;

import java.time.LocalDateTime;

public record ErrorDTO(String message,LocalDateTime timestamp) {
}
