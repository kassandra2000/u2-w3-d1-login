package kassandrafalsitta.u2w3d1.repositories;

import kassandrafalsitta.u2w3d1.entities.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface EmployeesRepository extends JpaRepository<Employee, UUID> {
    Optional<Employee> findByEmail(String email);

}
