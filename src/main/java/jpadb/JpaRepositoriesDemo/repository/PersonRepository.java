package jpadb.JpaRepositoriesDemo.repository;

import jpadb.JpaRepositoriesDemo.dao.Person;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PersonRepository extends JpaRepository<Person, Long> {

    @Query("SELECT t FROM Person t WHERE t.cityLiving = :city")
    List<Person> getPersonByCityLivingJPQL(@Param("city") String city);

    @Query("SELECT t FROM Person t WHERE t.age < :age ORDER BY t.age ASC")
    List<Person> getPersonByAgeLessThanOrderByAgeAscJPQL(@Param("age") Integer age);

    @Query("SELECT t FROM Person t WHERE t.name = :name AND t.surname = :surname")
    Optional<Person> getPersonByNameAndSurnameJPQL(@Param("name") String name, @Param("surname") String surname);

}