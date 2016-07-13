function(event) {
    if (/^hlx\.security\.user\-/.test(event._id) && event.seq_number) {
        emit(event.iso_date, 1);
    }
}
