from datetime import datetime

# Даты из условия
moscow_times_str = 'Wednesday, October 2, 2002'
guardian_str = 'Friday, 11.10.13'
daily_news_str = 'Thursday, 18 August 1977'

moscow_times_dt = datetime.strptime(moscow_times_str, '%A, %B %d, %Y')
guardian_dt = datetime.strptime(guardian_str, '%A, %d.%m.%y')
daily_news_dt = datetime.strptime(daily_news_str, '%A, %d %B %Y')

print(moscow_times_dt)
print(guardian_dt)
print(daily_news_dt)