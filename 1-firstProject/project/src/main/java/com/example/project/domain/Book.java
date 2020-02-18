package com.example.project.domain;

import javax.persistence.*;

@Entity
public class Book {

    @Id
    @GeneratedValue
    private Long id;

    private String title;

    @ManyToOne
    private Account author;

    public Account getAuthor() {
        return author;
    }

    public void setAuthor(Account author) {
        this.author = author;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }
}
