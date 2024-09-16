package kassandrafalsitta.u2w3d1.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@ToString
@Entity
@Table(name = "reservations")
public class Reservation {
    @Id
    @GeneratedValue
    @Setter(AccessLevel.NONE)
    private UUID id;
    private LocalDate dateRes;
    private String preferences;

    @ManyToOne
    @JoinColumn(name = "travel_id")
    private Travel travel;
    @ManyToOne
    @JoinColumn(name = "employee_id")
    private Employee employee;
    //costruttore
    public Reservation( LocalDate dateRes, String preferences, Travel travel, Employee employee) {
        this.dateRes = dateRes;
        this.preferences = preferences;
        this.travel = travel;
        this.employee = employee;
    }
}
