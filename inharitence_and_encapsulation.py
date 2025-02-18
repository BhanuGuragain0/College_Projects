import re
import time
from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

init()
console = Console()

def cyber_art_shadow():
    art = """
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗██╗   ██╗ 
██   █║ ██║  ██║██╔══██╗████╗  ██║██║   ██║
█████║  ███████║███████║██╔██╗ ██║██║   ██║
██   █║ ██╔══██║██╔══██║██║╚██╗██║██║   ██║
██████║ ██║  ██║██║  ██║██║ ╚████║╚██████╔╝
╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚════╝  
"""
    rprint(f"[bold magenta]{art}[/bold magenta]")
    rprint(f"[bold red][ THE SHADOW HACKER EMERGES ][/bold red]")

# User Class
class User:
    def __init__(self, name, email):
        self.name = name
        self.email = email
        self.validate_email(email)

    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(pattern, email):
            rprint(f"[bold red]Email Ramrari herera hal:[/bold red] {email}")
            raise ValueError()
        else:
            rprint(f"[bold green]Email {email} is valid from google[/bold green]")

    def get_email(self):
        return self.email

    def set_email(self, new_email):
        self.validate_email(new_email)
        self.email = new_email
        rprint(f"[yellow]Email change vayo {self.email} to {new_email}[/yellow]")

    def display_email(self):
        rprint(f"[cyan]Sale ta {self.name} ko email yo ho {self.email}[/cyan]")

# Member Class
class Member(User):
    def __init__(self, name, email, ID):
        super().__init__(name, email)
        self.__ID = ID
        self.__liyeko_book = []

    def borrow_book(self, library, book_title):
        if len(self.__liyeko_book) > 5:
            rprint(f"[bold red]{self.name} yo kitab {book_title} naam gareko haru 5 ota vanda badi lana paudainas[/bold red]")
            return
        if library.is_book_available(book_title):
            self.__liyeko_book.append(book_title)
            library.remove_book(book_title)
            rprint(f"[bold green]Book '{book_title}' borrowed successfully.[/bold green]")
        else:
            rprint(f"[bold red]Book '{book_title}' is not available or taile lagi sakis[/bold red]")

    def return_book(self, library, book_title):
        if book_title in self.__liyeko_book:
            self.__liyeko_book.remove(book_title)
            library.add_book(book_title)
            rprint(f"[bold green]Book '{book_title}' returned successfully.[/bold green]")
        else:
            rprint(f"[bold red]Book '{book_title}' not borrowed by {self.name}.[/bold red]")

    def display_borrowed_books(self):
        if self.__liyeko_book:
            rprint(f"[cyan]{self.name} ko kitab yo ho {self.__liyeko_book}[/cyan]")
        else:
            rprint(f"[yellow]{self.name} ko kitab nai ho[/yellow]")

# Librarian Class
class Librarian(User):
    def __init__(self, name, email, employee_id):
        super().__init__(name, email)
        self.__employee_id = employee_id

    def add_book(self, library, book_title):
        library.add_book(book_title)

    def remove_book(self, library, book_title):
        library.remove_book(book_title)

# Library Class
class Library:
    def __init__(self):
        self.__books = {}

    def add_book(self, title):
        if title in self.__books:
            rprint(f"[bold red]Book '{title}' agadi bata nai xa.[/bold red]")
            return
        self.__books[title] = "Unknown Author"
        rprint(f"[bold green]Tero yo '{title}' kitab add vayo.[/bold green]")

    def remove_book(self, title):
        if title not in self.__books:
            rprint(f"[bold red]Book '{title}' kina remove gareko feri hal chutiya 2 minutes vitra.[/bold red]")
            return
        del self.__books[title]
        rprint(f"[bold green]Book '{title}' pahilai bata xaina ghanta khojeko[/bold green]")

    def is_book_available(self, title):
        return title in self.__books

    def display_books(self):
        if self.__books:
            rprint("[bold cyan]Available Books:[/bold cyan]")
            for title, author in self.__books.items():
                rprint(f"[cyan]{title} by {author}[/cyan]")
        else:
            rprint("[yellow]Kitab vetiyena hai.[/yellow]")

    def search_books(self, query):
        results = [title for title in self.__books if query.lower() in title.lower()]
        if results:
            rprint("[bold cyan]Search Results:[/bold cyan]")
            for title in results:
                rprint(f"[cyan]{title} by {self.__books[title]}[/cyan]")
        else:
            rprint("[yellow]Tero kitab match nai gardaina.[/yellow]")

# Loading Animation
def loading_animation():
    console.print("[bold blue]Processing", end="")
    for _ in range(3):
        time.sleep(0.5)
        console.print(".", end="")
    console.print("")

# Main Library Simulation Function
def library_simulation():
    library = Library()
    librarian = Librarian("Bhanu", "bhanukoemailxaina@gmail.com", "LR1")
    member = Member("Sujit", "khaisujitkoemailmalaiktha@gmail.com", "SR1")

    while True:
        cyber_art_shadow()
        console.rule("[bold magenta]Library System")
        options = """
        [bold yellow]1[/]. Library ma naya kitab hal (Librarian)
        [bold yellow]2[/]. Kitab hatauxas? (Librarian)
        [bold yellow]3[/]. Sabai kitab herxas
        [bold yellow]4[/]. Kitab khoj
        [bold yellow]5[/]. Kitab lag (Member)
        [bold yellow]6[/]. Firta Gareko Kitab (Member)
        [bold yellow]7[/]. Lageko Kitab Her (Member)
        [bold yellow]8[/]. Exit
        """
        console.print(Panel(options, style="bold cyan", title="[bold magenta]Choose an Action"))

        choice = input("[bold yellow]K chha tero bichar k garxas yo library system ma: [/bold yellow]")
        if choice == '1':
            title = input("Kitab KO naam Van: ")
            loading_animation()
            librarian.add_book(library, title)
        elif choice == '2':
            title = input("Kun kitab hatauxas gadha van: ")
            loading_animation()
            librarian.remove_book(library, title)
        elif choice == '3':
            loading_animation()
            library.display_books()
        elif choice == '4':
            query = input("Kun Kitab khojna lageko naam lekh na: ")
            loading_animation()
            library.search_books(query)
        elif choice == '5':
            title = input("Kun Kitab lagna lageko naam lekh na: ")
            loading_animation()
            member.borrow_book(library, title)
        elif choice == '6':
            title = input("Kun kitab firta garna aako gadha van: ")
            loading_animation()
            member.return_book(library, title)
        elif choice == '7':
            loading_animation()
            member.display_borrowed_books()
        elif choice == '8':
            rprint("[bold green]Ramrari padh gadha ya bata exit gari halis reel herne haina tya[/bold green]")
            break
        else:
            rprint("[bold red]Tero choice sahi xaina. Try again.[/bold red]")

if __name__ == "__main__":
    library_simulation()
