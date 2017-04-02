function(event) {
    if (/^hlx\.security\.user\-/.test(event._id)) {
        emit([ event.aggregate_root_identifier, event.seq_number ], 1);
    }
}