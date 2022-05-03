from datetime import datetime
from dataclasses import dataclass


#EXPLICAÇÃO "TYPE" DA OPERAÇÃO:
COMPRA = "1"
VENDA = "0"

@dataclass(frozen=True)
class Transaction:
    id: int
    name: str
    type: int
    amount: int
    time_created: datetime
    price_purchased_at: float
    no_of_coins: float
    user_id: str


def format_db_row_to_transaction(row):
    return Transaction(
        id=row[0],
        name=row[1],
        type=row[2],
        amount=row[3]/100,
        price_purchased_at=float(row[4]),
        no_of_coins=float(row[5]),
        time_created=row[6].strftime("%d/%m/%Y"),
        user_id=row[7],
    )