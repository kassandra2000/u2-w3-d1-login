package kassandrafalsitta.u2w3d1.controllers;

import jakarta.validation.Valid;
import kassandrafalsitta.u2w2d5.entities.Employee;
import kassandrafalsitta.u2w2d5.exceptions.BadRequestException;
import kassandrafalsitta.u2w2d5.payloads.EmployeeDTO;
import kassandrafalsitta.u2w2d5.payloads.EmployeeRespDTO;
import kassandrafalsitta.u2w2d5.services.EmployeesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.context.support.DefaultMessageSourceResolvable;


import java.io.IOException;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/employees")
public class EmployeesController {
    @Autowired
    private EmployeesService employeesService;

    @GetMapping
    public Page<Employee> getAllEmployees(@RequestParam(defaultValue = "0") int page,
                                        @RequestParam(defaultValue = "10") int size,
                                        @RequestParam(defaultValue = "id") String sortBy) {
        return this.employeesService.findAll(page, size, sortBy);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public EmployeeRespDTO createEmployee(@RequestBody  @Validated EmployeeDTO body, BindingResult validationResult) {
        if(validationResult.hasErrors())  {
            String messages = validationResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .collect(Collectors.joining(". "));
            throw new BadRequestException("Ci sono stati errori nel payload. " + messages);
        } else {
            return new EmployeeRespDTO(this.employeesService.saveEmployee(body).getId());
        }
    }

    @GetMapping("/{employeeId}")
    public Employee getEmployeeById(@PathVariable UUID employeeId) {
        return employeesService.findById(employeeId);
    }

    @PutMapping("/{employeeId}")
    public Employee findEmployeeByIdAndUpdate(@PathVariable UUID employeeId, @RequestBody @Validated EmployeeDTO body) {
        return employeesService.findByIdAndUpdate(employeeId, body);
    }

    @DeleteMapping("/{employeeId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void findEmployeeByIdAndDelete(@PathVariable UUID employeeId) {
        employeesService.findByIdAndDelete(employeeId);
    }

    @PostMapping("/{employeeId}/avatar")
    public Employee uploadCover(@PathVariable UUID employeeId, @RequestParam("avatar") MultipartFile image) throws IOException {
        return  this.employeesService.uploadImage(employeeId,image);
    }

}
