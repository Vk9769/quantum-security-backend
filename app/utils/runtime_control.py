STOP_FLAGS = set()
PAUSE_FLAGS = set()


def stop_scan(scan_id):
    STOP_FLAGS.add(scan_id)


def pause_scan(scan_id):
    PAUSE_FLAGS.add(scan_id)


def resume_scan(scan_id):
    PAUSE_FLAGS.discard(scan_id)
    STOP_FLAGS.discard(scan_id)


def is_stopped(scan_id):
    return scan_id in STOP_FLAGS


def is_paused(scan_id):
    return scan_id in PAUSE_FLAGS