package jpadb.JpaRepositoriesDemo.controller;

import jpadb.JpaRepositoriesDemo.dao.Person;
import jpadb.JpaRepositoriesDemo.repository.PersonRepository;
import jpadb.JpaRepositoriesDemo.service.ServiceByPersons;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/person")
public class ControllerByPersons {
    private final ServiceByPersons service;

    public ControllerByPersons(ServiceByPersons service) {
        this.service = service;
    }

    @GetMapping("/city")
    public ResponseEntity<List<Person>> getResponsByCity(@RequestParam("city")String city){
        return ResponseEntity.ok(service.getPersonsByCity(city));
    }

    @GetMapping("/age")
    public ResponseEntity<List<Person>> getResponsByAge(@RequestParam("age")Integer age){
        return ResponseEntity.ok(service.getPersonByAgeOrderAsc(age));
    }
    @GetMapping("/name-surname")
    public ResponseEntity<Optional<Person>> getPersonByNameSurname(@RequestParam("name") String name, @RequestParam("surname") String surname) {
        return ResponseEntity.ok(service.getPersonByNameSurname(name, surname));
    }


}
