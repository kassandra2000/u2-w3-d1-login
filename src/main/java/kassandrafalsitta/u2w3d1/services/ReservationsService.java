package kassandrafalsitta.u2w3d1.services;

import kassandrafalsitta.u2w3d1.entities.Employee;
import kassandrafalsitta.u2w3d1.entities.Reservation;
import kassandrafalsitta.u2w3d1.entities.Travel;
import kassandrafalsitta.u2w3d1.exceptions.BadRequestException;
import kassandrafalsitta.u2w3d1.exceptions.NotFoundException;
import kassandrafalsitta.u2w3d1.payloads.ReservationDTO;
import kassandrafalsitta.u2w3d1.repositories.ReservationsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.UUID;

@Service
public class ReservationsService {
    @Autowired
    private ReservationsRepository reservationsRepository;
    @Autowired
    private EmployeesService employeesService;
    @Autowired
    private TravelsService travelsService;

    public Page<Reservation> findAll(int page, int size, String sortBy) {
        if (page > 100) page = 100;
        Pageable pageable = PageRequest.of(page, size, Sort.by(sortBy));
        return this.reservationsRepository.findAll(pageable);
    }

    public Reservation saveReservation(ReservationDTO body) {
        LocalDate dateRes = null;
        try {
            dateRes = LocalDate.parse(body.dateRes());
        } catch (DateTimeParseException e) {
            throw new BadRequestException("Il formato della data non è valido: " + body.dateRes()+" inserire nel seguente formato: AAAA-MM-GG");
        }

        UUID employeeID = null;
        try {
            employeeID = UUID.fromString(body.employeeID());
        } catch (NumberFormatException e) {
            throw new BadRequestException("L'UUID del dipendente non è corretto");
        }
        UUID travelID = null;
        try {
            travelID = UUID.fromString(body.travelID());
        } catch (NumberFormatException e) {
            throw new BadRequestException("L'UUID del viaggio non è corretto");
        }
        Travel travel = travelsService.findById(travelID);
        Employee employee = employeesService.findById(employeeID);
        this.reservationsRepository.findByEmployeeIdAndTravel_DateTrav(employeeID,travel.getDateTrav()).ifPresent(
                reservation -> {
                    throw new BadRequestException("La data " + body.dateRes() + " è già in uso per il dipendente " + body.employeeID());
                }
        );


        Reservation reservation = new Reservation(dateRes, body.preferences(), travel, employee);
        return this.reservationsRepository.save(reservation);
    }

    public Reservation findById(UUID reservationId) {
        return this.reservationsRepository.findById(reservationId).orElseThrow(() -> new NotFoundException(reservationId));
    }

    public Reservation findByIdAndUpdate(UUID reservationId, ReservationDTO updatedReservation) {
        UUID employeeID = null;
        try {
            employeeID = UUID.fromString(updatedReservation.employeeID());
        } catch (DateTimeParseException e) {
            throw new BadRequestException("L'UUID del dipendente non è corretto");
        }
        UUID travelID = null;
        try {
            employeeID = UUID.fromString(updatedReservation.travelID());
        } catch (DateTimeParseException e) {
            throw new BadRequestException("L'UUID del viaggio non è corretto");
        }
        Reservation found = findById(reservationId);
        LocalDate date = null;
        try {
            date = LocalDate.parse(updatedReservation.dateRes());
        } catch (DateTimeParseException e) {
            throw new BadRequestException("Il formato della data non è valido: " + updatedReservation.dateRes()+" inserire nel seguente formato: AAAA/MM/GG");
        }
        found.setDateRes(date);
        found.setPreferences(updatedReservation.preferences());
        Travel travel = travelsService.findById(travelID);
        Employee employee = employeesService.findById(employeeID);
        found.setTravel(travel);
        found.setEmployee(employee);
        return this.reservationsRepository.save(found);
    }

    public void findByIdAndDelete(UUID reservationId) {
        this.reservationsRepository.delete(this.findById(reservationId));
    }
}
