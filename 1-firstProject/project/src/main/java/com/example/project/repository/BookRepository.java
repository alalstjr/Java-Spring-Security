package com.example.project.repository;

import com.example.project.domain.Book;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface BookRepository extends JpaRepository<Book, Long> {

    @Query("select b from Book b where b.author.id = ?#{principal.account.id}")
    List<Book> findCurrentUserBooks();
}
