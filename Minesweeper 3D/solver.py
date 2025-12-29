import random
from copy import deepcopy
from time import sleep
import time
from pwn import *
import traceback

r = remote("localhost", 9999, timeout=60 * 60)

delay = 0.5


def timer(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        print(f"Function {func.__name__} took {time.time() - start:.2f} seconds")
        return result

    return wrapper


def print_map(gamemap):
    gamemap = deepcopy(gamemap)
    for layer in gamemap:
        for i in range(len(layer)):
            for j in range(len(layer[i])):
                if isinstance(layer[i][j], int):
                    layer[i][j] = str(layer[i][j])
    layers = []
    for layer in gamemap:
        layers.append("\n".join(["".join(i) for i in layer]))
    return "\n\n".join(layers)


def is_digit(map, i, j, k):
    return isinstance(map[i][j][k], int)


def iterate_map(map):
    for i in range(len(map)):
        for j in range(len(map[i])):
            for k in range(len(map[i][j])):
                yield i, j, k


_cache = {}
def iterate_map_border(map):
    if "iterate_map_border" in _cache:
        items = _cache["iterate_map_border"]
    else:
        items = set()
        for i, j, k in iterate_map(map):
            if map[i][j][k] == ".":
                items.add((i, j, k))
                for ii, jj, kk in iterate_neighbors(map, i, j, k):
                    items.add((ii, jj, kk))
        items = sorted(list(items))
        # _cache["iterate_map_border"] = items
    for i, j, k in items:
        yield i, j, k


def iterate_neighbors(map, i, j, k):
    for di in range(-1, 2):
        for dj in range(-1, 2):
            for dk in range(-1, 2):
                if di == 0 and dj == 0 and dk == 0:
                    continue
                if (
                    0 <= i + di < len(map)
                    and 0 <= j + dj < len(map[i])
                    and 0 <= k + dk < len(map[i][j])
                ):
                    yield i + di, j + dj, k + dk


def iterate_neighbors_2(map, i, j, k):
    for di in range(-2, 3):
        for dj in range(-2, 3):
            for dk in range(-2, 3):
                if di == 0 and dj == 0 and dk == 0:
                    continue
                if (
                    0 <= i + di < len(map)
                    and 0 <= j + dj < len(map[i])
                    and 0 <= k + dk < len(map[i][j])
                ):
                    yield i + di, j + dj, k + dk


@timer
def open_safe_cells(map):
    total_opens = 0
    round_opens = 0
    for i, j, k in iterate_map_border(map):
        if map[i][j][k] in ["!", ".", 0]:
            continue
        mine_count = 0
        for ii, jj, kk in iterate_neighbors(map, i, j, k):
            if map[ii][jj][kk] == "!":
                mine_count += 1
        if mine_count == map[i][j][k] and map[i][j][k] > 0:
            for ii, jj, kk in iterate_neighbors(map, i, j, k):
                if map[ii][jj][kk] == ".":
                    open(ii, jj, kk)
                    total_opens += 1
                    round_opens += 1

    return total_opens


@timer
def mark_obvious_mines(map):
    total_actions = 0
    for i, j, k in iterate_map_border(map):
        if map[i][j][k] == ".":
            continue
        possible_mines = 0
        guessed_mines = 0
        for ii, jj, kk in iterate_neighbors(map, i, j, k):
            if map[ii][jj][kk] == ".":
                possible_mines += 1
            if map[ii][jj][kk] == "!":
                guessed_mines += 1
        if possible_mines + guessed_mines == map[i][j][k] and map[i][j][k] > 0:
            for ii, jj, kk in iterate_neighbors(map, i, j, k):
                if map[ii][jj][kk] == ".":
                    mark(ii, jj, kk)
                    map[ii][jj][kk] = "!"
                    total_actions += 1

    return total_actions


def get_hidden_cells(map, i, j, k):
    hidden_cells = []
    for ii, jj, kk in iterate_neighbors(map, i, j, k):
        if map[ii][jj][kk] == ".":
            hidden_cells.append((ii, jj, kk))
    return hidden_cells


def get_mines(map, i, j, k):
    mines = []
    for ii, jj, kk in iterate_neighbors(map, i, j, k):
        if map[ii][jj][kk] == "!":
            mines.append((ii, jj, kk))
    return mines


@timer
def guess_mines_for_two_cells(map):
    total_actions = 0
    for i, j, k in iterate_map(map):
        if not is_digit(map, i, j, k):
            continue
        hidden_cells_1 = get_hidden_cells(map, i, j, k)
        mines_1 = get_mines(map, i, j, k)
        if len(hidden_cells_1) == 0:
            continue
        for ii, jj, kk in iterate_map(map):
            if not is_digit(map, ii, jj, kk):
                continue
            hidden_cells_2 = get_hidden_cells(map, ii, jj, kk)
            mines_2 = get_mines(map, ii, jj, kk)
            if len(hidden_cells_2) == 0:
                continue
            intersection = set(hidden_cells_1) & set(hidden_cells_2)
            if len(intersection) == 0:
                continue
            max_mines_intersection = min(
                len(intersection),
                map[i][j][k] - len(mines_1),
                map[ii][jj][kk] - len(mines_2),
            )
            subset_1 = set(hidden_cells_1) - intersection
            subset_2 = set(hidden_cells_2) - intersection

            min_mines_intersection = max(
                map[i][j][k] - len(mines_1) - len(subset_1),
                map[ii][jj][kk] - len(mines_2) - len(subset_2),
                0,
            )

            if (
                map[i][j][k] - len(mines_1) - max_mines_intersection == len(subset_1)
                and len(subset_1) > 0
            ):
                for iii, jjj, kkk in subset_1:
                    if map[iii][jjj][kkk] == "!":
                        continue
                    mark(iii, jjj, kkk)
                    map[iii][jjj][kkk] = "!"
                    total_actions += 1

            if (
                map[i][j][k] - len(mines_1) - min_mines_intersection == 0
                and len(subset_1) > 0
            ):
                for iii, jjj, kkk in subset_1:
                    open(iii, jjj, kkk)
                    total_actions += 1

            if (
                map[ii][jj][kk] - len(mines_2) - max_mines_intersection == len(subset_2)
                and len(subset_2) > 0
            ):
                for iii, jjj, kkk in subset_2:
                    if map[iii][jjj][kkk] == "!":
                        continue
                    mark(iii, jjj, kkk)
                    map[iii][jjj][kkk] = "!"
                    total_actions += 1

            if (
                map[ii][jj][kk] - len(mines_2) - min_mines_intersection == 0
                and len(subset_2) > 0
            ):
                for iii, jjj, kkk in subset_2:
                    open(iii, jjj, kkk)
                    total_actions += 1

    return total_actions


def validate_mine(map, i, j, k):
    for ii, jj, kk in iterate_neighbors(map, i, j, k):
        if not is_digit(map, ii, jj, kk):
            continue
        mines = get_mines(map, ii, jj, kk)
        if len(mines) > map[ii][jj][kk]:
            return False
    return True


@timer
def guess_mines_by_amount(map, n, should_full=False):
    hidden_cells = []
    hidden_cells_full = []
    mines_count = 0
    for i, j, k in iterate_map(map):
        if map[i][j][k] == "!":
            mines_count += 1
            continue
        if should_full and map[i][j][k] == ".":
            hidden_cells_full.append((i, j, k))
        if is_digit(map, i, j, k):
            hidden_cells.extend(get_hidden_cells(map, i, j, k))
    hidden_cells = sorted(list(set(hidden_cells)))
    hidden_cells_full = sorted(list(set(hidden_cells_full)))
    if should_full and len(hidden_cells_full) != len(hidden_cells):
        return False

    max_mines = n - mines_count

    possible_cases = 0
    possible_maps = []

    def set_mines(map, hidden_cells, max_mines, idx=0):
        nonlocal possible_cases
        nonlocal possible_maps
        for i, j, k in iterate_map(map):
            if not is_digit(map, i, j, k):
                continue
            if map[i][j][k] != len(get_mines(map, i, j, k)):
                break
        else:
            if not should_full or idx == max_mines:
                possible_cases += 1
                last_map = deepcopy(map)
                possible_maps.append(last_map)

        if idx == max_mines:
            return
        for l, (i, j, k) in enumerate(hidden_cells):
            map[i][j][k] = "!"
            if not validate_mine(map, i, j, k):
                map[i][j][k] = "."
                continue
            set_mines(map, hidden_cells[l + 1 :], max_mines, idx + 1)
            map[i][j][k] = "."
        return

    set_mines(map, hidden_cells, max_mines)
    if should_full and possible_cases != 1:
        return False
    union_mines = []
    union_digits = []
    for i, j, k in hidden_cells:
        if map[i][j][k] != ".":
            continue
        for possible_map in possible_maps:
            if possible_map[i][j][k] != "!":
                break
        else:
            union_mines.append((i, j, k))
        for possible_map in possible_maps:
            if possible_map[i][j][k] == "!":
                break
        else:
            union_digits.append((i, j, k))

    if len(union_mines) == 0 and len(union_digits) == 0:
        return False

    for i, j, k in union_mines:
        map[i][j][k] = mark(i, j, k)

    for i, j, k in union_digits:
        map[i][j][k] = open(i, j, k)
    return True


@timer
def guess_mines_by_neighbors(map):
    for i, j, k in iterate_map(map):
        if not is_digit(map, i, j, k):
            continue
        hidden_cells_1 = get_hidden_cells(map, i, j, k)
        mines_1 = get_mines(map, i, j, k)
        possible_mines = map[i][j][k] - len(mines_1)
        if len(hidden_cells_1) == 0:
            continue

        for ii, jj, kk in iterate_neighbors_2(map, i, j, k):
            if not is_digit(map, ii, jj, kk):
                continue
            hidden_cells_2 = get_hidden_cells(map, ii, jj, kk)
            if len(hidden_cells_2) == 0:
                continue
            intersection = set(hidden_cells_1) & set(hidden_cells_2)
            if len(intersection) != len(hidden_cells_2):
                continue
            mines_2 = get_mines(map, ii, jj, kk)
            hidden_cells_1 = list(set(hidden_cells_1) - intersection)
            possible_mines -= map[ii][jj][kk] - len(mines_2)
            if possible_mines == len(hidden_cells_1) and len(hidden_cells_1) > 0:
                for iii, jjj, kkk in hidden_cells_1:
                    mark(iii, jjj, kkk)
                    map[iii][jjj][kkk] = "!"
                return 1
            if possible_mines == 0 and len(hidden_cells_1) > 0:
                for iii, jjj, kkk in hidden_cells_1:
                    map[iii][jjj][kkk] = open(iii, jjj, kkk)
                return 1
    return 0


def validate(map, n):
    total_mines = 0
    for i, j, k in iterate_map(map):
        if map[i][j][k] == ".":
            return False
        if map[i][j][k] == "!":
            total_mines += 1

    if total_mines != n:
        return False
    return True


def open_all_cells(map):
    for i, j, k in iterate_map(map):
        if map[i][j][k] == ".":
            map[i][j][k] = open(i, j, k)


def mark_all_cells(map):
    for i, j, k in iterate_map(map):
        if map[i][j][k] == ".":
            map[i][j][k] = "!"


@timer
def get_submaps(map):
    submaps = []

    total_mask = []
    current_mask = []
    all_masks = []

    queue = []

    for i, j, k in iterate_map(map):
        if (i, j, k) in total_mask:
            continue
        if is_digit(map, i, j, k) or map[i][j][k] == "!":
            continue
        queue.append((i, j, k))
        while len(queue) > 0:
            i, j, k = queue.pop(0)
            if (i, j, k) in total_mask:
                continue
            total_mask.append((i, j, k))
            current_mask.append((i, j, k))
            if is_digit(map, i, j, k):
                continue
            for ii, jj, kk in iterate_neighbors(map, i, j, k):
                if (ii, jj, kk) in total_mask:
                    continue
                if (ii, jj, kk) in queue:
                    continue
                queue.append((ii, jj, kk))
            for ii, jj, kk in iterate_neighbors_2(map, i, j, k):
                if (ii, jj, kk) in total_mask:
                    continue
                if (ii, jj, kk) in queue:
                    continue
                if map[ii][jj][kk] == ".":
                    queue.append((ii, jj, kk))
        if len(current_mask) < 2:
            current_mask = []
            continue
        all_masks.append(current_mask)
        current_mask = []

    all_masks.sort(key=lambda x: len(x))

    for mask in all_masks:
        submap = deepcopy(map)
        for i, j, k in iterate_map(submap):
            if (i, j, k) not in mask:
                submap[i][j][k] = 0
        submaps.append(submap)
    return submaps


@timer
def solve_mine(map, n):
    global _cache
    _cache = {}

    hidden_cells = []
    for (
        i,
        j,
        k,
    ) in iterate_map(map):
        if map[i][j][k] == ".":
            hidden_cells.append((i, j, k))

    if len(hidden_cells) == 0:
        r.sendline(b"done")
        return True

    if open_safe_cells(map):
        return False
    if mark_obvious_mines(map):
        return False

    submaps = get_submaps(map)
    for submap in submaps:
        if guess_mines_for_two_cells(submap):
            return False
        if guess_mines_by_neighbors(submap):
            return False
    if guess_mines_by_amount(map, n):
        return False

    mines_count = 0
    for i, j, k in iterate_map(map):
        if map[i][j][k] == "!":
            mines_count += 1
    if mines_count == n:
        open_all_cells(map)

    hidden_cells_count = 0
    for i, j, k in iterate_map(map):
        if map[i][j][k] == ".":
            hidden_cells_count += 1
    if hidden_cells_count == n - mines_count:
        mark_all_cells(map)
    if validate(map, n):
        return False

    if guess_mines_by_amount(map, n, should_full=True):
        return False

    hidden_cells = []
    for (
        i,
        j,
        k,
    ) in iterate_map(map):
        if map[i][j][k] == ".":
            hidden_cells.append((i, j, k))

    open(*random.choice(hidden_cells))

    return False


def get_map_params():
    r.sendline(b"info")
    r.recvuntil(b"Field size: ")
    size = r.recvline().decode("ascii")
    w, h, d = map(int, size.split("x"))
    r.recvuntil(b"Mines left: ")
    n = int(r.recvline().decode("ascii").strip())
    r.clean()
    return w, h, d, n


def get_map(depth):
    global delay
    print(set_cursor(0, 0, 0, delay=delay * 2))
    map_full = []
    for i in range(depth):
        message = set_cursor(i, 0, 0, delay=delay)
        lines = message.split("\n")[5:-3]
        lines = [list(line[2:-2]) for line in lines]
        for i in range(len(lines)):
            for j in range(len(lines[i])):
                if lines[i][j].isdigit():
                    lines[i][j] = int(lines[i][j])
                elif lines[i][j] in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    lines[i][j] = 10 + ord(lines[i][j]) - ord("A")
        map_full.append(lines)
    r.clean()
    return map_full


def open(x, y, z):
    set_cursor(x, y, z)
    r.sendline("open".encode("ascii"))
    a = r.clean().decode("ascii")
    if "nto" in a:
        print(a)
    return a


def mark(z, y, x):
    set_cursor(z, y, x)
    r.sendline("flag".encode("ascii"))
    r.clean()


def set_cursor(z, y, x, delay=0.0):
    time.sleep(delay)
    r.clean()
    r.sendline(f"cursor {x} {y} {z}".encode("ascii"))
    time.sleep(delay)
    return r.clean().decode("ascii")


step = 1

while step <= 7:
    print("step", step)
    r.recvuntil(b"Field size: ")
    w, h, d, n = get_map_params()
    map_full = get_map(d)
    while True:
        try:
            ww, hh, dd, nn = get_map_params()
            if w != ww or h != hh or d != dd:
                break
            if solve_mine(map_full, n):
                print("solved")
                step += 1
                break
            map_full = get_map(d)
            print(print_map(map_full))
            print()
            print()
        except EOFError as e:
            traceback.print_exc()
            break
        except Exception as e:
            traceback.print_exc()
r.interactive()
