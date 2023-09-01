import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from random import choice, randint
from time import time
from urllib.parse import urlsplit, urlunsplit

from apis import PanelSession, TempEmail, guess_panel, panel_class_map
from subconverter import gen_base64_and_clash_config, get
from utils import (clear_files, g0, keep, list_file_paths, list_folder_paths,
                   rand_id, read, read_cfg, remove, size2str, str2timestamp,
                   timestamp2str, to_zero, write, write_cfg)


def get_sub(session: PanelSession, opt: dict, cache: dict[str, list[str]]):
    url = cache['sub_url'][0]
    suffix = ' - ' + g0(cache, 'name')
    if 'speed_limit' in opt:
        suffix += ' ⚠️限速 ' + opt['speed_limit']
    try:
        info, *rest = get(url, suffix)
    except Exception:
        origin = urlsplit(session.origin)[:2]
        url = '|'.join(urlunsplit(origin + urlsplit(part)[2:]) for part in url.split('|'))
        info, *rest = get(url, suffix)
        cache['sub_url'][0] = url
    if not info and hasattr(session, 'get_sub_info'):
        session.login(cache['email'][0])
        info = session.get_sub_info()
    return info, *rest


def should_turn(session: PanelSession, opt: dict, cache: dict[str, list[str]]):
    if 'sub_url' not in cache:
        return 1,

    now = time()
    try:
        info, *rest = get_sub(session, opt, cache)
    except Exception as e:
        msg = str(e)
        if '邮箱' in msg and ('不存在' in msg or '禁' in msg or '黑' in msg):
            if (d := cache['email'][0].split('@')[1]) not in ('gmail.com', 'qq.com', g0(cache, 'email_domain')):
                cache['banned_domains'].append(d)
            return 2,
        raise e

    return int(
        not info
        or opt.get('turn') == 'always'
        or float(info['total']) - (float(info['upload']) + float(info['download'])) < (1 << 28)
        or (opt.get('expire') != 'never' and info.get('expire') and str2timestamp(info.get('expire')) - now < ((now - str2timestamp(cache['time'][0])) / 7 if 'reg_limit' in opt else 2400))
    ), info, *rest


def _register(session: PanelSession, email, *args, **kwargs):
    try:
        return session.register(email, *args, **kwargs)
    except Exception as e:
        raise Exception(f'注册失败({email}): {e}')


def _get_email_and_email_code(kwargs, session: PanelSession, opt: dict, cache: dict[str, list[str]]):
    while True:
        tm = TempEmail(banned_domains=cache.get('banned_domains'))
        try:
            email = kwargs['email'] = tm.email
        except Exception as e:
            raise Exception(f'获取邮箱失败: {e}')
        try:
            session.send_email_code(email)
        except Exception as e:
            msg = str(e)
            if '禁' in msg or '黑' in msg:
                cache['banned_domains'].append(email.split('@')[1])
                continue
            raise Exception(f'发送邮箱验证码失败({email}): {e}')
        email_code = tm.get_email_code(g0(cache, 'name'))
        if not email_code:
            cache['banned_domains'].append(email.split('@')[1])
            raise Exception(f'获取邮箱验证码超时({email})')
        kwargs['email_code'] = email_code
        return email


def register(session: PanelSession, opt: dict, cache: dict[str, list[str]], log: list) -> bool:
    kwargs = keep(opt, 'name_eq_email', 'reg_fmt', 'aff')

    if 'invite_code' in cache:
        kwargs['invite_code'] = cache['invite_code'][0]
    elif 'invite_code' in opt:
        kwargs['invite_code'] = choice(opt['invite_code'].split())

    email = kwargs['email'] = f"{rand_id()}@{g0(cache, 'email_domain', default='gmail.com')}"
    while True:
        if not (msg := _register(session, **kwargs)):
            if g0(cache, 'auto_invite', 'T') == 'T' and hasattr(session, 'get_invite_info'):
                if 'buy' not in opt and 'invite_code' not in kwargs:
                    session.login()
                    try:
                        code, num, money = session.get_invite_info()
                    except Exception as e:
                        if g0(cache, 'auto_invite') == 'T':
                            log.append(f'{session.host}({email}): {e}')
                        if '邀请' in str(e):
                            cache['auto_invite'] = 'F'
                        return False
                    if 'auto_invite' not in cache:
                        if not money:
                            cache['auto_invite'] = 'F'
                            return False
                        balance = session.get_balance()
                        plan = session.get_plan(min_price=balance + 0.01, max_price=balance + money)
                        if not plan:
                            cache['auto_invite'] = 'F'
                            return False
                        cache['auto_invite'] = 'T'
                    cache['invite_code'] = [code, num]
                    kwargs['invite_code'] = code

                    session.reset()

                    if 'email_code' in kwargs:
                        email = _get_email_and_email_code(kwargs, session, opt, cache)
                    else:
                        email = kwargs['email'] = f"{rand_id()}@{email.split('@')[1]}"

                    if (msg := _register(session, **kwargs)):
                        break

                if 'invite_code' in kwargs:
                    if 'invite_code' not in cache or int(cache['invite_code'][1]) == 1 or randint(0, 1):
                        session.login()
                        try_buy(session, opt, cache, log)
                        try:
                            cache['invite_code'] = [*session.get_invite_info()[:2]]
                        except Exception as e:
                            if 'invite_code' not in cache:
                                cache['auto_invite'] = 'F'
                            else:
                                log.append(f'{session.host}({email}): {e}')
                        return True
                    else:
                        n = int(cache['invite_code'][1])
                        if n > 0:
                            cache['invite_code'][1] = n - 1
            return False
        if '后缀' in msg:
            if email.split('@')[1] != 'gmail.com':
                break
            email = kwargs['email'] = f'{rand_id()}@qq.com'
        elif '验证码' in msg:
            email = _get_email_and_email_code(kwargs, session, opt, cache)
        elif '联' in msg:
            kwargs['im_type'] = True
        elif (
            '邀请人' in msg
            and g0(cache, 'invite_code', '') == kwargs.get('invite_code')
        ):
            del cache['invite_code']
            if 'invite_code' in opt:
                kwargs['invite_code'] = choice(opt['invite_code'].split())
            else:
                del kwargs['invite_code']
        else:
            break
    raise Exception(f'注册失败({email}): {msg}{" " + kwargs.get("invite_code") if "邀" in msg else ""}')


def is_checkin(session, opt: dict):
    return hasattr(session, 'checkin') and opt.get('checkin') != 'F'


def try_checkin(session: PanelSession, opt: dict, cache: dict[str, list[str]], log: list):
    if is_checkin(session, opt) and cache.get('email'):
        if len(cache['last_checkin']) < len(cache['email']):
            cache['last_checkin'] += ['0'] * (len(cache['email']) - len(cache['last_checkin']))
        last_checkin = to_zero(str2timestamp(cache['last_checkin'][0]))
        now = time()
        if now - last_checkin > 24.5 * 3600:
            try:
                session.login(cache['email'][0])
                session.checkin()
                cache['last_checkin'][0] = timestamp2str(now)
                cache.pop('尝试签到失败', None)
            except Exception as e:
                cache['尝试签到失败'] = [e]
                log.append(f'尝试签到失败({session.host}): {e}')
    else:
        cache.pop('last_checkin', None)


def try_buy(session: PanelSession, opt: dict, cache: dict[str, list[str]], log: list):
    try:
        if (plan := opt.get('buy')):
            return session.buy(plan)
        if (plan := g0(cache, 'buy')):
            if plan == 'pass':
                return False
            try:
                return session.buy(plan)
            except Exception as e:
                del cache['buy']
                cache.pop('auto_invite', None)
                cache.pop('invite_code', None)
                log.append(f'上次购买成功但这次购买失败({session.host}): {e}')
        plan = session.buy()
        cache['buy'] = plan or 'pass'
        return plan
    except Exception as e:
        log.append(f'购买失败({session.host}): {e}')
    return False


def do_turn(session: PanelSession, opt: dict, cache: dict[str, list[str]], log: list, force_reg=False) -> bool:
    is_new_reg = False
    login_and_buy_ok = False
    reg_limit = opt.get('reg_limit')
    if not reg_limit:
        login_and_buy_ok = register(session, opt, cache, log)
        is_new_reg = True
        cache['email'] = [session.email]
        if is_checkin(session, opt):
            cache['last_checkin'] = ['0']
    else:
        reg_limit = int(reg_limit)
        if len(cache['email']) < reg_limit or force_reg:
            login_and_buy_ok = register(session, opt, cache, log)
            is_new_reg = True
            cache['email'].append(session.email)
            if is_checkin(session, opt):
                cache['last_checkin'] += ['0'] * (len(cache['email']) - len(cache['last_checkin']))
        if len(cache['email']) > reg_limit:
            del cache['email'][:-reg_limit]
            if is_checkin(session, opt):
                del cache['last_checkin'][:-reg_limit]

        cache['email'] = cache['email'][-1:] + cache['email'][:-1]
        if is_checkin(session, opt):
            cache['last_checkin'] = cache['last_checkin'][-1:] + cache['last_checkin'][:-1]

    if not login_and_buy_ok:
        try:
            session.login(cache['email'][0])
        except Exception as e:
            raise Exception(f'登录失败: {e}')
        try_buy(session, opt, cache, log)

    try_checkin(session, opt, cache, log)
    cache['sub_url'] = [session.get_sub_url(**opt)]
    cache['time'] = [timestamp2str(time())]
    log.append(f'{"更新订阅链接(新注册)" if is_new_reg else "续费续签"}({session.host}) {cache["sub_url"][0]}')


def try_turn(session: PanelSession, opt: dict, cache: dict[str, list[str]], log: list):
    cache.pop('更新旧订阅失败', None)
    cache.pop('更新订阅链接/续费续签失败', None)
    cache.pop('获取订阅失败', None)

    try:
        turn, *sub = should_turn(session, opt, cache)
    except Exception as e:
        cache['更新旧订阅失败'] = [e]
        log.append(f'更新旧订阅失败({session.host})({cache["sub_url"][0]}): {e}')
        return None

    if turn:
        try:
            do_turn(session, opt, cache, log, force_reg=turn == 2)
        except Exception as e:
            cache['更新订阅链接/续费续签失败'] = [e]
            log.append(f'更新订阅链接/续费续签失败({session.host}): {e}')
            return sub
        try:
            sub = get_sub(session, opt, cache)
        except Exception as e:
            cache['获取订阅失败'] = [e]
            log.append(f'获取订阅失败({session.host})({cache["sub_url"][0]}): {e}')

    return sub


def cache_sub_info(info, opt: dict, cache: dict[str, list[str]]):
    if not info:
        raise Exception('no sub info')
    used = float(info["upload"]) + float(info["download"])
    total = float(info["total"])
    rest = '(剩余 ' + size2str(total - used)
    if opt.get('expire') == 'never' or not info.get('expire'):
        expire = '永不过期'
    else:
        ts = str2timestamp(info['expire'])
        expire = timestamp2str(ts)
        rest += ' ' + str(timedelta(seconds=ts - time()))
    rest += ')'
    cache['sub_info'] = [size2str(used), size2str(total), expire, rest]


def save_sub_base64_and_clash(base64, clash, host, opt: dict):
    return gen_base64_and_clash_config(
        base64_path=f'trials/{host}',
        clash_path=f'trials/{host}.yaml',
        providers_dir=f'trials_providers/{host}',
        base64=base64,
        clash=clash,
        exclude=opt.get('exclude')
    )


def save_sub(info, base64, clash, base64_url, clash_url, host, opt: dict, cache: dict[str, list[str]], log: list):
    cache.pop('保存订阅信息失败', None)
    cache.pop('保存base64/clash订阅失败', None)

    try:
        cache_sub_info(info, opt, cache)
    except Exception as e:
        cache['保存订阅信息失败'] = [e]
        log.append(f'保存订阅信息失败({host})({clash_url}): {e}')
    try:
        node_n = save_sub_base64_and_clash(base64, clash, host, opt)
        if (d := node_n - int(g0(cache, 'node_n', 0))) != 0:
            log.append(f'{host} 节点数 {"+" if d > 0 else ""}{d} ({node_n})')
        cache['node_n'] = node_n
    except Exception as e:
        cache['保存base64/clash订阅失败'] = [e]
        log.append(f'保存base64/clash订阅失败({host})({base64_url})({clash_url}): {e}')


def get_and_save(session: PanelSession, host, opt: dict, cache: dict[str, list[str]], log: list):
    try_checkin(session, opt, cache, log)
    sub = try_turn(session, opt, cache, log)
    if sub:
        save_sub(*sub, host, opt, cache, log)


def new_panel_session(host, cache: dict[str, list[str]], log: list) -> PanelSession | None:
    if 'type' not in cache:
        info = guess_panel(host)
        if 'type' not in info:
            if (e := info.get('error')):
                log.append(f"{host} 判别类型失败: {e}")
            else:
                log.append(f"{host} 未知类型")
            return None
        cache.update(info)
    return panel_class_map[g0(cache, 'type')](g0(cache, 'api_host', host), **keep(cache, 'auth_path', getitem=g0))


def get_trial(host, opt: dict, cache: dict[str, list[str]]):
    log = []
    session = new_panel_session(host, cache, log)
    if session:
        get_and_save(session, host, opt, cache, log)
        if session.redirect_origin:
            cache['api_host'] = session.host
    return log


def build_options(cfg):
    opt = {
        host: dict(zip(opt[::2], opt[1::2]))
        for host, *opt in cfg
    }
    return opt


if __name__ == '__main__':
    pre_repo = read('.github/repo_get_trial')
    cur_repo = os.getenv('GITHUB_REPOSITORY')
    if pre_repo != cur_repo:
        remove('trial.cache')
        write('.github/repo_get_trial', cur_repo)

    cfg = read_cfg('trial.cfg')['default']

    opt = build_options(cfg)

    cache = read_cfg('trial.cache', dict_items=True)

    for host in [*cache]:
        if host not in opt:
            del cache[host]

    for path in list_file_paths('trials'):
        host, ext = os.path.splitext(os.path.basename(path))
        if ext != '.yaml':
            host += ext
        else:
            host = host.split('_')[0]
        if host not in opt:
            remove(path)

    for path in list_folder_paths('trials_providers'):
        host = os.path.basename(path)
        if '.' in host and host not in opt:
            clear_files(path)
            remove(path)

    with ThreadPoolExecutor(32) as executor:
        args = [(h, opt[h], cache[h]) for h, *_ in cfg]
        for log in executor.map(get_trial, *zip(*args)):
            for line in log:
                print(line)

    total_node_n = gen_base64_and_clash_config(
        base64_path='trial',
        clash_path='trial.yaml',
        providers_dir='trials_providers',
        base64_paths=(path for path in list_file_paths('trials') if os.path.splitext(path)[1].lower() != '.yaml'),
        providers_dirs=(path for path in list_folder_paths('trials_providers') if '.' in os.path.basename(path))
    )

    print('总节点数', total_node_n)

    write_cfg('trial.cache', cache)
