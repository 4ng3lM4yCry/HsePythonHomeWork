from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Union, TypeAlias


@dataclass(frozen=True)
class OperationRecord:
    """Запись об операции по счету."""
    op_type: str                    # 'deposit' | 'withdraw'
    amount: float
    timestamp: str
    balance_after: float
    status: str                     # 'success' | 'fail'
    reason: Optional[str] = None
    credit_used: Optional[bool] = None  # None для Account, True/False для CreditAccount


OperationHistory: TypeAlias = Union[List[Dict[str, Any]], List[OperationRecord]]


class Account:
    """
    Базовый счёт:
    - баланс не может быть отрицательным;
    - deposit/withdraw логируются;
    - get_history возвращает историю в удобном виде.
    """

    MAX_BALANCE: float = 1e12
    MAX_AMOUNT: float = 1e9

    def __init__(self, account_holder: str, balance: float = 0.0) -> None:
        if not isinstance(account_holder, str) or not account_holder.strip():
            raise ValueError("account_holder должен быть непустой строкой")

        bal = self._to_float(balance)
        if bal < 0:
            raise ValueError("Начальный баланс не может быть отрицательным для Account")

        self.holder: str = account_holder.strip()
        self.operations_history: List[OperationRecord] = []
        self._balance: float = 0.0
        self._set_balance(bal)

    # ---------- Валидация / утилиты ----------

    @staticmethod
    def _now_str() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _to_float(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Невозможно преобразовать '{value}' в число") from e

    @classmethod
    def _validate_amount_positive(cls, amount: Any) -> float:
        value = cls._to_float(amount)
        if value <= 0:
            raise ValueError("Сумма должна быть положительной")
        if abs(value) > cls.MAX_AMOUNT:
            raise ValueError("Сумма слишком большая")
        return value

    def _validate_balance_limits(self, balance: float) -> None:
        if abs(balance) > self.MAX_BALANCE:
            raise ValueError("Баланс превышает допустимые пределы")

    def _set_balance(self, value: float) -> None:
        """Защищённая установка баланса с проверками (для наследников тоже)."""
        self._validate_balance_limits(value)
        self._balance = value

    def _log_operation(
        self,
        op_type: str,
        amount: float,
        status: str,
        reason: Optional[str] = None,
        credit_used: Optional[bool] = None,
    ) -> None:
        self.operations_history.append(
            OperationRecord(
                op_type=op_type,
                amount=amount,
                timestamp=self._now_str(),
                balance_after=self._balance,
                status=status,
                reason=reason,
                credit_used=credit_used,
            )
        )

    # ---------- API ----------

    def deposit(self, amount: Any) -> bool:
        """Пополнение (успех/неуспех)."""
        try:
            value = self._validate_amount_positive(amount)
            new_balance = self._balance + value
            self._set_balance(new_balance)
            self._log_operation("deposit", value, "success", credit_used=None)
            return True
        except ValueError as e:
            amt = self._to_float(amount) if self._can_float(amount) else 0.0
            self._log_operation("deposit", amt, "fail", reason=str(e), credit_used=None)
            return False

    def withdraw(self, amount: Any) -> bool:
        """Снятие (Account не уходит в минус)."""
        try:
            value = self._validate_amount_positive(amount)
            if self._balance < value:
                self._log_operation(
                    "withdraw",
                    value,
                    "fail",
                    reason="Недостаточно средств",
                    credit_used=None,
                )
                return False

            new_balance = self._balance - value
            self._set_balance(new_balance)
            self._log_operation("withdraw", value, "success", credit_used=None)
            return True
        except ValueError as e:
            amt = self._to_float(amount) if self._can_float(amount) else 0.0
            self._log_operation("withdraw", amt, "fail", reason=str(e), credit_used=None)
            return False

    def get_balance(self) -> float:
        return self._balance

    def get_history(self, *, as_dict: bool = True) -> OperationHistory:
        """
        Возвращает историю операций в удобном формате:
        - as_dict=True: List[Dict] (по умолчанию)
        - as_dict=False: List[OperationRecord]
        """
        if as_dict:
            return [asdict(rec) for rec in self.operations_history]
        return list(self.operations_history)

    @staticmethod
    def _can_float(value: Any) -> bool:
        try:
            float(value)
            return True
        except (TypeError, ValueError):
            return False


class CreditAccount(Account):
    """
    Кредитный счёт:
    - баланс может быть отрицательным, но не ниже -credit_limit;
    - get_available_credit() показывает доступные средства с учётом лимита;
    - операции логируются с credit_used=True/False.
    """

    def __init__(
        self,
        account_holder: str,
        balance: float = 0.0,
        credit_limit: float = 0.0,
    ) -> None:
        limit = self._to_float(credit_limit)
        if limit <= 0:
            raise ValueError("credit_limit должен быть положительным числом")

        # Инициализируем базовые поля без обходов: Account с 0,
        # а затем установим реальный баланс через _set_balance_with_credit().
        super().__init__(account_holder=account_holder, balance=0.0)

        self.credit_limit: float = limit
        bal = self._to_float(balance)
        self._set_balance_with_credit(bal)

    def _set_balance_with_credit(self, value: float) -> None:
        """Установка баланса с учётом кредитного лимита."""
        self._validate_balance_limits(value)
        if value < -self.credit_limit:
            raise ValueError("Баланс не может быть ниже -credit_limit")
        self._balance = value

    def get_available_credit(self) -> float:
        """Доступные средства = баланс + кредитный лимит."""
        return self._balance + self.credit_limit

    def deposit(self, amount: Any) -> bool:
        """Пополнение кредитного счёта."""
        try:
            value = self._validate_amount_positive(amount)
            new_balance = self._balance + value
            self._set_balance_with_credit(new_balance)
            self._log_operation("deposit", value, "success", credit_used=False)
            return True
        except ValueError as e:
            amt = self._to_float(amount) if self._can_float(amount) else 0.0
            self._log_operation("deposit", amt, "fail", reason=str(e), credit_used=False)
            return False

    def withdraw(self, amount: Any) -> bool:
        """Снятие с учётом лимита."""
        try:
            value = self._validate_amount_positive(amount)
            new_balance = self._balance - value

            credit_used = new_balance < 0  # упрощение (п.3)

            if new_balance < -self.credit_limit:
                self._log_operation(
                    "withdraw",
                    value,
                    "fail",
                    reason="Превышение кредитного лимита",
                    credit_used=credit_used,
                )
                return False

            self._set_balance_with_credit(new_balance)
            self._log_operation("withdraw", value, "success", credit_used=credit_used)
            return True
        except ValueError as e:
            amt = self._to_float(amount) if self._can_float(amount) else 0.0
            self._log_operation("withdraw", amt, "fail", reason=str(e), credit_used=False)
            return False


# -----------------------
# Мини-тесты граничных случаев (п.8)
# -----------------------
def test_credit_limit() -> None:
    acc = CreditAccount("Test", balance=-100, credit_limit=200)
    assert acc.get_balance() == -100
    assert acc.get_available_credit() == 100


def test_account_no_negative_start() -> None:
    try:
        Account("A", -1)
        assert False, "Должно было упасть"
    except ValueError:
        assert True


def test_withdraw_over_limit_fails() -> None:
    acc = CreditAccount("T", balance=0, credit_limit=100)
    ok = acc.withdraw(150)
    assert ok is False
    assert acc.get_balance() == 0


def test_amount_validation() -> None:
    acc = Account("X", 10)
    assert acc.deposit("abc") is False
    assert acc.withdraw(-5) is False


if __name__ == "__main__":
    # Запуск мини-тестов
    test_credit_limit()
    test_account_no_negative_start()
    test_withdraw_over_limit_fails()
    test_amount_validation()
    print("OK: tests passed")

