package kassandrafalsitta.u2w3d1.entities;

import jakarta.persistence.*;
import kassandrafalsitta.u2w3d1.enums.StateTravel;
import lombok.*;

import java.time.LocalDate;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@ToString
@Entity
@Table(name = "travels")
public class Travel {
    @Id
    @GeneratedValue
    @Setter(AccessLevel.NONE)
    private UUID id;
    private String destination;
    private LocalDate dateTrav;
    @Enumerated(EnumType.STRING)
    private StateTravel stateTravel;
    //costruttore
    public Travel( String destination, LocalDate dateTrav, StateTravel stateTravel) {
        this.destination = destination;
        this.dateTrav = dateTrav;
        this.stateTravel = stateTravel;
    }
}
