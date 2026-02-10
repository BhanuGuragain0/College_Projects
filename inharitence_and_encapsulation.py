#!/usr/bin/env python3
"""
Advanced Library System

This Python‑based application is designed for real‑world library management. It allows librarians to add or remove books
and members to borrow or return books (with a maximum limit of 5). With animated feedback, robust error handling, and detailed
logging, this system provides a professional user experience.

Usage:
    python library_system.py
"""

import re
import time
import logging
from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

# Initialize Colorama and Rich Console
init(autoreset=True)
console = Console()

# Configure logging for detailed output
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def cyber_art_shadow() -> None:
    art = """
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗██╗   ██╗ 
██   █║ ██║  ██║██╔══██╗████╗  ██║██║   ██║
█████║  ███████║███████║██╔██╗ ██║██║   ██║
██   █║ ██╔══██║██╔══██║██║╚██╗██║██║   ██║
██████║ ██║  ██║██║  ██║██║ ╚████║╚██████╔╝
╚═════╝  ╚═╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚════╝  
"""
    rprint(f"[bold magenta]{art}[/bold magenta]")
    rprint(f"[bold red][ THE SHADOW HACKER EMERGES ][/bold red]")


# Base User class with email validation
class User:
    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email
        self.validate_email(email)

    @staticmethod
    def validate_email(email: str) -> None:
        pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(pattern, email):
            rprint(f"[bold red]Invalid email address:[/bold red] {email}")
            raise ValueError("Invalid email address")
        else:
            rprint(f"[bold green]Email '{email}' is valid.[/bold green]")

    def get_email(self) -> str:
        return self.email

    def set_email(self, new_email: str) -> None:
        old_email = self.email
        self.validate_email(new_email)
        self.email = new_email
        rprint(f"[yellow]Email changed from {old_email} to {new_email}.[/yellow]")
        logging.info(f"User {self.name} changed email from {old_email} to {new_email}.")

    def display_email(self) -> None:
        rprint(f"[cyan]User {self.name}'s email is: {self.email}[/cyan]")


# LibraryMember class (for both general and student members)
class LibraryMember(User):
    def __init__(self, name: str, email: str, member_id: str, max_books: int = 5):
        super().__init__(name, email)
        self.member_id = member_id
        self.borrowed_books = []

    def borrow_book(self, library, book_title: str) -> None:
        if len(self.borrowed_books) >= 5:
            rprint(f"[bold red]{self.name} cannot borrow '{book_title}'; maximum limit of {5} books reached.[/bold red]")
            logging.error(f"{self.name} reached borrowing limit.")
            return
        if book_title in self.borrowed_books:
            rprint(f"[bold yellow]{self.name} has already borrowed '{book_title}'.[/bold yellow]")
            logging.warning(f"{self.name} attempted duplicate borrow for '{book_title}'.")
            return
        if library.is_book_available(book_title):
            self.borrowed_books.append(book_title)
            library.remove_book(book_title)
            rprint(f"[bold green]Book '{book_title}' borrowed successfully by {self.name}.[/bold green]")
            logging.info(f"{self.name} borrowed '{book_title}'.")
        else:
            rprint(f"[bold red]Book '{book_title}' is not available in the library.[/bold red]")
            logging.error(f"{book_title} not available for borrowing.")
        self._loading_animation("Borrow")

    def return_book(self, library, book_title: str) -> None:
        if book_title in self.borrowed_books:
            self.borrowed_books.remove(book_title)
            library.add_book(book_title)
            rprint(f"[bold green]Book '{book_title}' returned successfully by {self.name}.[/bold green]")
            logging.info(f"{self.name} returned '{book_title}'.")
        else:
            rprint(f"[bold red]Book '{book_title}' was not borrowed by {self.name}.[/bold red]")
            logging.error(f"{self.name} attempted to return unborrowed book '{book_title}'.")
        self._loading_animation("Return")

    def display_borrowed_books(self) -> None:
        if self.borrowed_books:
            rprint(f"[cyan]{self.name}'s borrowed books: {self.borrowed_books}[/cyan]")
        else:
            rprint(f"[yellow]{self.name} has not borrowed any books.[/yellow]")

    def _loading_animation(self, action: str) -> None:
        print(Fore.YELLOW + f"{action} in progress", end="", flush=True)
        for _ in range(3):
            time.sleep(0.5)
            print(Fore.YELLOW + ".", end="", flush=True)
        print("\n" + Fore.GREEN + f"{action} completed!" + Style.RESET_ALL)


# StudentMember inherits from LibraryMember and has additional privileges
class StudentMember(LibraryMember):
    def access_study_room(self) -> None:
        rprint(f"[bold magenta]\nStudent {self.name} (ID: {self.member_id}) is accessing the study room.[/bold magenta]")
        self._loading_animation("Study Room Access")


# Librarian class with privileges to add or remove books
class Librarian(User):
    def __init__(self, name: str, email: str, employee_id: str):
        super().__init__(name, email)
        self.employee_id = employee_id

    def add_book(self, library, book_title: str) -> None:
        library.add_book(book_title)
        logging.info(f"Librarian {self.name} added '{book_title}' to the library.")

    def remove_book(self, library, book_title: str) -> None:
        library.remove_book(book_title)
        logging.info(f"Librarian {self.name} removed '{book_title}' from the library.")


# Library class maintains a collection of books
class Library:
    def __init__(self):
        self.books = {}

    def add_book(self, title: str) -> None:
        if title in self.books:
            rprint(f"[bold red]Book '{title}' already exists in the library.[/bold red]")
            logging.warning(f"Attempt to add duplicate book '{title}'.")
            return
        self.books[title] = "Unknown Author"
        rprint(f"[bold green]Book '{title}' added successfully to the library.[/bold green]")

    def remove_book(self, title: str) -> None:
        if title not in self.books:
            rprint(f"[bold red]Book '{title}' not found in the library.[/bold red]")
            logging.error(f"Attempt to remove non-existent book '{title}'.")
            return
        del self.books[title]
        rprint(f"[bold green]Book '{title}' removed successfully from the library.[/bold green]")

    def is_book_available(self, title: str) -> bool:
        return title in self.books

    def display_books(self) -> None:
        if self.books:
            rprint("[bold cyan]Available Books in the Library:[/bold cyan]")
            for title, author in self.books.items():
                rprint(f"[cyan]{title} by {author}[/cyan]")
        else:
            rprint("[yellow]No books available in the library.[/yellow]")

    def search_books(self, query: str) -> None:
        results = [title for title in self.books if query.lower() in title.lower()]
        if results:
            rprint("[bold cyan]Search Results:[/bold cyan]")
            for title in results:
                rprint(f"[cyan]{title} by {self.books[title]}[/cyan]")
        else:
            rprint("[yellow]No matching books found.[/yellow]")


def loading_animation() -> None:
    print(Fore.BLUE + "Processing", end="", flush=True)
    for _ in range(3):
        time.sleep(0.5)
        print(Fore.BLUE + ".", end="", flush=True)
    print("")


def display_menu() -> None:
    options = """
[bold yellow]1[/bold yellow]. Add a new book (Librarian)
[bold yellow]2[/bold yellow]. Remove a book (Librarian)
[bold yellow]3[/bold yellow]. Display all available books
[bold yellow]4[/bold yellow]. Search for a book
[bold yellow]5[/bold yellow]. Borrow a book (Member)
[bold yellow]6[/bold yellow]. Return a borrowed book (Member)
[bold yellow]7[/bold yellow]. Display borrowed books (Member)
[bold yellow]8[/bold yellow]. Exit
    """
    console.print(Panel(options, style="bold cyan", title="[bold magenta]Choose an Action"))


def library_simulation() -> None:
    library = Library()
    librarian = Librarian("Bhanu", "bhanukoemailxaina@gmail.com", "LR1")
    member = StudentMember("Sujit", "khaisujitkoemailmalaiktha@gmail.com", "SR1")

    # Pre-populate the library with some books for simulation
    initial_books = [
        "Programming and Algorithms",
        "Practical Pen-Testing",
        "Skills Development",
        "Programming Foundations",
        "Platforms and Operating Systems",
        "Digital Forensic Fundamentals",
        "Computer Systems & Networks",
        "Legal and Ethical Foundations in Cyber Security",
        "Introduction to Web Development and Database Systems",
        "The Security Professional",
        "Creative Thinking for Business",
        "Foundations of Cyber Security"
    ]
    for book in initial_books:
        library.add_book(book)

    try:
        while True:
            cyber_art_shadow()
            console.rule("[bold magenta]Library System[/bold magenta]")
            display_menu()
            choice = input("[bold yellow]Enter your choice: [/bold yellow]").strip()
            if choice == '1':
                title = input("Enter the book title to add: ").strip()
                loading_animation()
                librarian.add_book(library, title)
            elif choice == '2':
                title = input("Enter the book title to remove: ").strip()
                loading_animation()
                librarian.remove_book(library, title)
            elif choice == '3':
                loading_animation()
                library.display_books()
            elif choice == '4':
                query = input("Enter the book title to search for: ").strip()
                loading_animation()
                library.search_books(query)
            elif choice == '5':
                title = input("Enter the book title to borrow: ").strip()
                loading_animation()
                member.borrow_book(library, title)
            elif choice == '6':
                title = input("Enter the book title to return: ").strip()
                loading_animation()
                member.return_book(library, title)
            elif choice == '7':
                loading_animation()
                member.display_borrowed_books()
            elif choice == '8':
                rprint("[bold green]Exiting the library system. Thank you![/bold green]")
                break
            else:
                rprint("[bold red]Invalid choice. Please try again.[/bold red]")
            time.sleep(1)
    except KeyboardInterrupt:
        rprint("\n[bold red]Exiting due to user interruption.[/bold red]")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    library_simulation()
