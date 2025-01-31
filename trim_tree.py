from SmartMongoDB import SmartMongoDB

from SMARTORGCLASS import smartorgclass

import argparse
import csv

from collections import Counter

from datetime import datetime

import os
from dotenv import load_dotenv


# Load environment variables from the .env file
load_dotenv()
# Get the username and password
username = os.getenv("USERNAME")
password = os.getenv("PASSWORD")
server = os.getenv("SERVER")


class color:
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    DARKCYAN = "\033[36m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[32;5m"
    END = "\033[0m"



def generate_unique_filename(prefix="file", extension=".csv"):
    """
    Generate a unique filename using the current date and time.

    :param prefix: The prefix for the filename (default: "file").
    :param extension: The file extension (default: ".txt").
    :return: A unique filename as a string.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # YYYYMMDD_HHMMSS
    return f"{prefix}_{timestamp}{extension}"

def clear_console():
    os.system("cls" if os.name == "nt" else "clear")  # 'cls' for Windows, 'clear' for Linux/macOS


def confirm_proceed():
    """
    Asks the user to confirm whether to proceed (Y/N).
    Returns True if 'Y', False if 'N'.
    """
    while True:
        user_input = input("Are you sure you want to proceed? (Y/N): ").strip().lower()
        
        if user_input in ['y', 'yes']:
            print("Proceeding...\n")
            return True
        elif user_input in ['n', 'no']:
            print("Operation canceled.\n")
            return False
        else:
            print("Invalid input. Please enter 'Y' for Yes or 'N' for No.")





def create_portfolio(name, categories):
    print(f"Creating portfolio: {name}")
    print("Categories:")
    for i, category in enumerate(categories, start=1):
        print(f"  {i}. {category}")

def main():
   
    # Create the argument parser
    parser = argparse.ArgumentParser(
        description="Specify a portfolio to delete projects based on ProjectStatus"
     )

    # Add arguments
    parser.add_argument(
        "PortfolioName",
        type=str,
        help="The name of the portfolio"
    )
    parser.add_argument(
        "-c",
        "--categories",
        type=str,
        nargs="+",  # Accepts one or more categories
        required=True,  # Make it mandatory to use the -categories flag
        help="List of categories for the portfolio (provide after the -categories flag)"
    )

    # Parse the arguments
    args = parser.parse_args()

    treeID = args.PortfolioName
    filter = args.categories
    

    db = SmartMongoDB()

    if not db.portfolio_exists(treeID):
        print()
        print(f'Portfolio: "{treeID}" does not exist! Exiting!')
        print()
        return
    

    entries = db.project_status_entries

    # Find missing elements
    missing_entries = [item for item in filter if item not in entries]

    clear_console()

    if missing_entries:
        print(f'The following entries do not exist in the {color.BOLD}ProjectStatus{color.END} category for "{treeID}":')
        print(color.RED)
        for m in missing_entries:
            print(f'- {m}')

        print(color.END)
        print('Available entries are:')
        print(color.BLUE)
        for e in entries:
            print(f'- {e}')
        print(color.END)
        print('Exiting!')
        print()
        return
    
    clear_console()
    print(f'{color.BOLD}Please wait while finding the leaves to delete...{color.END}')
    trim_list = db.list_of_excluded_projects(filter)
    numNodes = len(trim_list)
    status_counts = Counter(d["ProjectStatus"] for d in trim_list)
    clear_console()
    

    print(f'Preparing to delete {color.BOLD}{numNodes}{color.END} leaf nodes from "{treeID}"')
    print()
    for f in filter:
        print(f'- {f} ({status_counts[f]} nodes)')
    print()

    # Example usage
    if confirm_proceed():
        prefix = treeID.replace(" ","_")
        filename = generate_unique_filename(prefix)

        

        clear_console()
        print("Continuing with the operation...")
        so = smartorgclass.SmartOrg(username, password,server, verify=False)
        with open(filename, "w", newline="",encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Cnt", "Path", "Node Name","ProjectStatus","NodeID"])
            for i,n in enumerate(trim_list):
                
                print(f'"{i+1}/{numNodes}", "{"→".join(db.get_node_names(n["path"]))}"', 
      f'"{n["name"]}", "{n["ProjectStatus"]}", "{n["_id"]}"')
                writer.writerow([f"{i+1}/{numNodes}","->".join(db.get_node_names(n["path"])),n['name'], n['ProjectStatus'], n['_id']])

                delete_lst = db.delete_node(n)
                
                for p in delete_lst[1:]:
                    print('"' + " " * len(f"{i+1}/{numNodes}") + '"' + 
      f', "{"→".join(db.get_node_names(p["path"]))}"', 
      f'"{p["name"]}", "{db.get_project_status(p["tags"])}", "{p["_id"]}"')
                    writer.writerow(["-"*len(f'{i+1}/{numNodes}'),"->".join(db.get_node_names(p['path'])),p['name'], db.get_project_status(p['tags']), p['_id']])
                
                deleteNodeID = delete_lst[-1]['_id']
                
                res = so.deleteNode(deleteNodeID)
                print(f'{len(res["deletedNodes"])} nodes deleted!  Node {deleteNodeID}')
                print()
    else:
        print()
        print("Exiting.")
        print()
        return
    

if __name__ == "__main__":
    main()
