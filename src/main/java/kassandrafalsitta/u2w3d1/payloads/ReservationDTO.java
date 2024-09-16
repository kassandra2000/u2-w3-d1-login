package kassandrafalsitta.u2w3d1.payloads;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;
import java.util.UUID;

public record ReservationDTO(
        @NotEmpty(message = "La data è obbligatoria")
        @Size(min = 10, max = 10, message = "La data deve avere 10 caratteri")
        String dateRes,
        @NotEmpty(message = "La preferenza è obbligatoria")
        @Size(min = 3, max = 100, message = "La preferenza deve essere compresa tra 3 e 100 caratteri")
        String preferences,
        @NotEmpty(message = "L'UUID del viaggio è obbligatorio")
        @Size(min = 36 , max = 36 , message = "L'UUID del viaggio  deve avere 36 caratteri")
         String travelID,
        @NotEmpty(message = "L'UUID del dipendente è obbligatorio")
        @Size(min = 36 , max = 36 , message = "L'UUID del dipendente  deve avere 36 caratteri")
         String employeeID
) {
}
