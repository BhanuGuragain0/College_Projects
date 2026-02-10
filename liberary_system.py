#!/usr/bin/env python3
"""
Advanced Library System

This script provides a robust implementation of a library management system for members.
It supports borrowing and returning books, displays animated status messages,
and logs significant actions and errors. The system is designed for real-world usage,
with added error handling and modular functions inspired by professional-grade tools.
"""

import logging
from time import sleep
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging for detailed debug and error information
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class LibraryMember:
    def __init__(self, name: str, student_id: str, section: str, max_books: int = 5):
        """
        Initialize a LibraryMember.

        Args:
            name (str): The member's name.
            student_id (str): The member's student ID.
            section (str): The section the member belongs to.
            max_books (int): Maximum number of books allowed to borrow.
        """
        self.name = name
        self.student_id = student_id
        self.section = section
        self.borrowed_books = []
        self.max_books = max_books

    def manage_book(self, book_name: str, action: str) -> None:
        """
        Borrow or return a book using a single method.

        Args:
            book_name (str): Name of the book.
            action (str): Action to perform, either 'borrow' or 'return'.
        """
        action = action.lower().strip()
        if action == "borrow":
            if book_name in self.borrowed_books:
                self._print_action(f"already borrowed '{book_name}'", Fore.YELLOW, error=True)
                logging.warning(f"{self.name} attempted to borrow a duplicate book: '{book_name}'.")
            elif len(self.borrowed_books) >= self.max_books:
                self._print_action(f"cannot borrow '{book_name}'; maximum limit reached ({self.max_books}).", Fore.RED, error=True)
                logging.error(f"{self.name} has reached the maximum borrow limit.")
            else:
                self.borrowed_books.append(book_name)
                self._print_action(f"borrowed '{book_name}'", Fore.GREEN)
                logging.info(f"{self.name} borrowed '{book_name}'.")
        elif action == "return":
            if book_name in self.borrowed_books:
                self.borrowed_books.remove(book_name)
                self._print_action(f"returned '{book_name}'", Fore.BLUE)
                logging.info(f"{self.name} returned '{book_name}'.")
            else:
                self._print_action(f"has not borrowed '{book_name}'", Fore.RED, error=True)
                logging.error(f"{self.name} attempted to return a book not borrowed: '{book_name}'.")
        else:
            self._print_action(f"invalid action '{action}' provided", Fore.RED, error=True)
            logging.error(f"Invalid action '{action}' for book management.")
            return

        self._loading_animation(action.capitalize())

    def list_borrowed_books(self) -> None:
        """
        List all books currently borrowed by the member.
        """
        if self.borrowed_books:
            books = ", ".join(self.borrowed_books)
            print(Fore.CYAN + f"{self.name} (ID: {self.student_id}) has borrowed: {books}" + Style.RESET_ALL)
        else:
            print(Fore.CYAN + f"{self.name} (ID: {self.student_id}) has not borrowed any books." + Style.RESET_ALL)

    def _print_action(self, action_message: str, color: str, error: bool = False) -> None:
        """
        Print an action message in the specified color.

        Args:
            action_message (str): The message describing the action.
            color (str): Color code for output.
            error (bool): Flag indicating an error message.
        """
        if error:
            icon = "❌"
        elif "returned" in action_message:
            icon = "🔄"
        elif "borrowed" in action_message:
            icon = "📚"
        else:
            icon = "ℹ️"
        print(f"{color}{icon} {self.name} (ID: {self.student_id}, Section: {self.section}) {action_message}.{Style.RESET_ALL}")

    @staticmethod
    def _loading_animation(action: str) -> None:
        """
        Display a simple loading animation.

        Args:
            action (str): The current action (e.g., 'Borrow', 'Return').
        """
        print(Fore.YELLOW + f"{action} in progress", end="", flush=True)
        for _ in range(3):
            sleep(0.5)
            print(Fore.YELLOW + ".", end="", flush=True)
        print("\n" + Fore.GREEN + f"{action} completed!" + Style.RESET_ALL)


class StudentMember(LibraryMember):
    def access_study_room(self) -> None:
        """
        Provide the student access to the study room.
        """
        print(Fore.MAGENTA + f"\n📖 Student {self.name} (ID: {self.student_id}, Section: {self.section}) is accessing the study room." + Style.RESET_ALL)
        self._loading_animation("Study Room Access")


# Example usage
if __name__ == "__main__":
    subjects = [
        "Programming and Algorithms",
        "Practical Pen-Testing",
        "Skills Development",
        "Programming Foundations",
        "Platforms and Operating Systems",
        "Digital Forensic Fundamentals",
        "Computer System & Networks",
        "Legal and Ethical Foundations in Cyber Security",
        "Introduction to Web Development and Database Systems",
        "The Security Professional",
        "Creative Thinking for Business",
        "Foundations of Cyber Security",
    ]

    print(Fore.LIGHTYELLOW_EX + "=== Generic Library Member Interaction ===" + Style.RESET_ALL)
    generic_member = LibraryMember("Aashish Panthi", "230364", "E35B")
    generic_member.manage_book(subjects[0], "borrow")
    generic_member.manage_book(subjects[0], "borrow")  # Attempt duplicate borrow
    generic_member.list_borrowed_books()
    generic_member.manage_book(subjects[0], "return")
    generic_member.manage_book("Nonexistent Subject", "return")
    generic_member.list_borrowed_books()

    print(Fore.LIGHTCYAN_EX + "\n=== Student Member Interaction ===" + Style.RESET_ALL)
    student_member = StudentMember("Bhanu Guragain", "230404", "E35B")
    student_member.manage_book(subjects[1], "borrow")
    student_member.manage_book(subjects[2], "borrow")
    student_member.manage_book(subjects[1], "return")
    student_member.list_borrowed_books()
    student_member.access_study_room()
