package kassandrafalsitta.u2w3d1.repositories;

import kassandrafalsitta.u2w3d1.entities.Travel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface TravelsRepository extends JpaRepository<Travel, UUID> {
    Optional<Travel> findByDateTravAndDestination(LocalDate date,String destination);


}
