package kassandrafalsitta.u2w3d1.services;

import kassandrafalsitta.u2w3d1.entities.Travel;
import kassandrafalsitta.u2w3d1.enums.StateTravel;
import kassandrafalsitta.u2w3d1.exceptions.BadRequestException;
import kassandrafalsitta.u2w3d1.exceptions.NotFoundException;
import kassandrafalsitta.u2w3d1.payloads.TravelDTO;
import kassandrafalsitta.u2w3d1.payloads.TravelStateDTO;
import kassandrafalsitta.u2w3d1.repositories.TravelsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Optional;
import java.util.UUID;

@Service
public class TravelsService {
    @Autowired
    private TravelsRepository travelsRepository;

    public Page<Travel> findAll(int page, int size, String sortBy) {
        if (page > 100) page = 100;
        Pageable pageable = PageRequest.of(page, size, Sort.by(sortBy));
        return this.travelsRepository.findAll(pageable);
    }

    public Travel saveTravel(TravelDTO body) {
        LocalDate dateTrav = null;
        try {
            dateTrav = LocalDate.parse(body.dateTrav());
        } catch ( DateTimeParseException e) {
            throw new BadRequestException("Il formato della data non è valido: " + body.dateTrav()+" inserire nel seguente formato: AAAA/MM/GG");
        }
        Optional<Travel> dateTravelAndDestination = travelsRepository.findByDateTravAndDestination(dateTrav,body.destination());
        if (dateTravelAndDestination.isPresent()) {
            throw new BadRequestException("La data " + body.dateTrav() + " e la destinazione " + body.destination() + " sono già in uso!");
        }
        StateTravel stateTravel = null;
        try {
             stateTravel = StateTravel.valueOf(body.stateTravel().toUpperCase());
        } catch (IllegalArgumentException e) {
           throw new BadRequestException("Stato del viaggio non valido: " + body.stateTravel());
        }


        Travel employee = new Travel(body.destination(), dateTrav, stateTravel);
        return this.travelsRepository.save(employee);
    }

    public Travel findById(UUID travelId) {
        return this.travelsRepository.findById(travelId).orElseThrow(() -> new NotFoundException(travelId));
    }

    public Travel findByIdAndUpdate(UUID reservationId, TravelDTO updatedTravel) {
        Travel found = findById(reservationId);
        LocalDate date = null;
        try {
            date = LocalDate.parse(updatedTravel.dateTrav());
        } catch (DateTimeParseException e) {
            throw new BadRequestException("Il formato della data non è valido: " + updatedTravel.dateTrav()+" inserire nel seguente formato: AAAA/MM/GG");
        }
        found.setDateTrav(date);
        StateTravel stateTravel = null;
        try {
            stateTravel = StateTravel.valueOf(updatedTravel.stateTravel());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Stato del viaggio non valido: " + updatedTravel.stateTravel());
        }
        found.setStateTravel(stateTravel);
        found.setDestination(updatedTravel.destination());
        return this.travelsRepository.save(found);
    }

    public void findByIdAndDelete(UUID travelId) {
        this.travelsRepository.delete(this.findById(travelId));
    }

    public Travel findByIdAndUpdateState(UUID reservationId, TravelStateDTO updatedStateTravel) {
        Travel found = findById(reservationId);
        StateTravel stateTravel = null;
        try {
            stateTravel = StateTravel.valueOf(updatedStateTravel.stateTravel().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Stato del viaggio non valido: " + updatedStateTravel.stateTravel());
        }
        found.setStateTravel(stateTravel);
        return this.travelsRepository.save(found);

    }
}
