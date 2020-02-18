package com.example.project.util;

import com.example.project.domain.Account;
import com.example.project.domain.Book;
import com.example.project.repository.BookRepository;
import com.example.project.service.AccountService;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class DefaultDataGenerator implements ApplicationRunner {

    private final AccountService accountService;
    private final BookRepository bookRepository;

    public DefaultDataGenerator(
            AccountService accountService,
            BookRepository bookRepository
    ) {
        this.accountService = accountService;
        this.bookRepository = bookRepository;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Account jjunpro = createAccount("jjunpro", "123", "USER");
        Account whiteship = createAccount("whiteship", "123", "USER");

        createBook(jjunpro,"spring");
        createBook(whiteship,"security");
    }

    private void createBook(Account jjunpro, String bookTitle) {
        Book book = new Book();
        book.setTitle(bookTitle);
        book.setAuthor(jjunpro);
        bookRepository.save(book);
    }

    private Account createAccount(String username, String password, String role) {
        Account account = new Account();
        account.setUsername(username);
        account.setPassword(password);
        account.setRole(role);

        return accountService.save(account);
    }
}
