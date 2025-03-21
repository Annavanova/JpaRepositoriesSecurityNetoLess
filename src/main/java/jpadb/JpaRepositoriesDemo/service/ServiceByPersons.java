package jpadb.JpaRepositoriesDemo.service;

import jpadb.JpaRepositoriesDemo.dao.Person;
import jpadb.JpaRepositoriesDemo.repository.PersonRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ServiceByPersons {
    private final PersonRepository repository;

    public ServiceByPersons(PersonRepository repository) {
        this.repository = repository;
    }

    public List<Person> getPersonsByCity(String city) {
        return repository.getPersonByCityLivingJPQL(city);
    }

    public List<Person> getPersonByAgeOrderAsc(Integer age) {
        return repository.getPersonByAgeLessThanOrderByAgeAscJPQL(age);
    }

    public Optional<Person> getPersonByNameSurname(String name, String surname) {
        return repository.getPersonByNameAndSurnameJPQL(name, surname);
    }
}
