package kassandrafalsitta.u2w3d1.payloads;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import kassandrafalsitta.u2w3d1.enums.StateTravel;

import java.time.LocalDate;

public record TravelDTO(
        @NotEmpty(message = "La destinazione è obbligatoria")
        @Size(min = 3, max = 30, message = "La destinazione deve essere compresa tra 3 e 30 caratteri")
        String destination,
        @NotEmpty(message = "La data è obbligatoria")
        @Size(min = 10, max = 10, message = "La data deve avere 10 caratteri")
        String dateTrav,
        @NotEmpty(message = "Lo stato è obbligatorio")
        String stateTravel
) {
}
