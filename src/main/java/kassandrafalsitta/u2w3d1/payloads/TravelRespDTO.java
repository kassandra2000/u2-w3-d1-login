package kassandrafalsitta.u2w3d1.payloads;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record TravelRespDTO(
        @NotNull(message = "L'UUID è obbligatorio")
        UUID travelId
) {
}
