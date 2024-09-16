package kassandrafalsitta.u2w3d1.services;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import kassandrafalsitta.u2w2d5.entities.Employee;
import kassandrafalsitta.u2w2d5.exceptions.BadRequestException;
import kassandrafalsitta.u2w2d5.exceptions.NotFoundException;
import kassandrafalsitta.u2w2d5.payloads.EmployeeDTO;
import kassandrafalsitta.u2w2d5.repositories.EmployeesRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.UUID;

@Service
public class EmployeesService {
    @Autowired
    private EmployeesRepository employeesRepository;

    @Autowired
    private Cloudinary cloudinaryUploader;

    public Page<Employee> findAll(int page, int size, String sortBy) {
        if (page > 100) page = 100;
        Pageable pageable = PageRequest.of(page, size, Sort.by(sortBy));
        return this.employeesRepository.findAll(pageable);
    }

    public Employee saveEmployee(EmployeeDTO body) {
        this.employeesRepository.findByEmail(body.email()).ifPresent(
                employee -> {
                    throw new BadRequestException("L'email " + body.email() + " è già in uso!");
                }
        );
        Employee employee = new Employee(body.username(), body.name(), body.surname(), body.email(), "https://ui-avatars.com/api/?name=" + body.name() + "+" + body.surname());
        return this.employeesRepository.save(employee);
    }

    public Employee findById(UUID employeeId) {
        return this.employeesRepository.findById(employeeId).orElseThrow(() -> new NotFoundException(employeeId));
    }

    public Employee findByIdAndUpdate(UUID employeeId, EmployeeDTO updatedEmployee) {
        Employee found = findById(employeeId);
        found.setUsername(updatedEmployee.username());
        found.setName(updatedEmployee.name());
        found.setSurname(updatedEmployee.surname());
        found.setEmail(updatedEmployee.email());
        return this.employeesRepository.save(found);
    }

    public void findByIdAndDelete(UUID employeeId) {
        this.employeesRepository.delete(this.findById(employeeId));
    }

    public Employee uploadImage(UUID employeeId, MultipartFile file) throws IOException {
        Employee found = findById(employeeId);
        String avatar = (String) cloudinaryUploader.uploader().upload(file.getBytes(), ObjectUtils.emptyMap()).get("url");
        found.setAvatar(avatar);
        return this.employeesRepository.save(found);
    }


}
