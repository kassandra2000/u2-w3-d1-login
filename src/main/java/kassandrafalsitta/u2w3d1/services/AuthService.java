package kassandrafalsitta.u2w3d1.services;

import kassandrafalsitta.u2w3d1.entities.Employee;
import kassandrafalsitta.u2w3d1.exceptions.UnauthorizedException;
import kassandrafalsitta.u2w3d1.payloads.EmployeeLoginDTO;
import kassandrafalsitta.u2w3d1.security.JWTTools;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    @Autowired
    private EmployeesService employeesService;

    @Autowired
    private JWTTools jwtTools;

    public String checkCredentialsAndGenerateToken(EmployeeLoginDTO body) {
        // 1. Controllo le credenziali
        // 1.1 Cerco nel db tramite email se esiste l'utente
        Employee found = this.employeesService.findByEmail(body.email());
        if (found.getPassword().equals(body.password())) {
            // 1.2 Se lo trovo verifico se la pw trovata combacia con quella passataci tramite body
            // 2. Se è tutto ok --> genero un access token e lo restituisco
            return jwtTools.createToken(found);
        } else {
            // 3. Se le credenziali sono errate --> 401 (Unauthorized)
            throw new UnauthorizedException("Credenziali errate!");
        }


    }
}
