package kassandrafalsitta.u2w3d1.controllers;

import kassandrafalsitta.u2w3d1.exceptions.BadRequestException;
import kassandrafalsitta.u2w3d1.payloads.EmployeeDTO;
import kassandrafalsitta.u2w3d1.payloads.EmployeeLoginDTO;
import kassandrafalsitta.u2w3d1.payloads.EmployeeLoginRespDTO;
import kassandrafalsitta.u2w3d1.payloads.EmployeeRespDTO;
import kassandrafalsitta.u2w3d1.services.AuthService;
import kassandrafalsitta.u2w3d1.services.EmployeesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private EmployeesService employeesService;

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public EmployeeLoginRespDTO login(@RequestBody EmployeeLoginDTO payload) {
        return new EmployeeLoginRespDTO(this.authService.checkCredentialsAndGenerateToken(payload));
    }


    @PostMapping("/register")
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
}
