use chrono::{Days, Local, NaiveDateTime};

pub fn get_datetime_from_now(days_from_now: u64) -> NaiveDateTime {
    let now = Local::now();
    now.checked_sub_days(Days::new(days_from_now)).unwrap().naive_local()
}