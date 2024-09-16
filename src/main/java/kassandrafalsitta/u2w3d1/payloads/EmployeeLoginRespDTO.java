package kassandrafalsitta.u2w3d1.payloads;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public record EmployeeLoginRespDTO(
        @NotEmpty(message = "L'accessToken è obbligatorio")
        @Size(min = 20, max = 300, message = "L'accessToken deve essere compreso tra 3 e 40 caratteri")
        String accessToken
) {
}
