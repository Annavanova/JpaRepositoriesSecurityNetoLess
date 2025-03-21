package jpadb.JpaRepositoriesDemo.dao;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "person")
public class Person {
    @Id
    @Column(name = "name", length = 50)
    private String name;

    @Id
    @Column(name = "surname", length = 50)
    private String surname;

    @Id
    @Column(name = "age", length = 100)
    @JdbcTypeCode(SqlTypes.INTEGER)
    private Integer age;

    @Column(name = "phone_number", length = 10)
    private String phonenumber;

    @Column(name = "city_of_living", length = 50)
    private String cityofliving;



}

