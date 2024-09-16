package kassandrafalsitta.u2w3d1.payloads;

import jakarta.validation.constraints.NotEmpty;

public record TravelStateDTO(
        @NotEmpty(message = "Lo stato è obbligatorio")
        String stateTravel
) {
}
