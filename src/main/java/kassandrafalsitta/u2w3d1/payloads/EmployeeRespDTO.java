package kassandrafalsitta.u2w3d1.payloads;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record EmployeeRespDTO(
        @NotNull(message = "L'UUID è obbligatorio")
        UUID employeeId
) {
}
