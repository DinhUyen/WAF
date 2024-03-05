class ModsecLog1(Base):
    __tablename__ = "modseclog1"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String)
    event_time = datetime
    remote_address = Column(String) 
    request_host = Column(String)
    local_port = Column(String)
    request_useragent = Column(String)
    request_line = Column(String)
    request_line_method = Column(String)
    request_line_url = Column(String)
    request_line_protocol = Column(String)
    response_protocol = Column(String)
    response_status = Column(String)
    action = Column(String)
    action_phase = Column(String)
    action_message = Column(String)
    message_type = Column(String)
    message_description = Column(String)
    message_rule_id = Column(String)
    message_rule_file = Column(String)
    message_msg = Column(String)
    message_severity = Column(String)
    message_accuracy = Column(String)
    message_maturity = Column(String)
    full_message_line = Column(String)

SQLITE_DATABASE_URL  = "sqlite:////home/kali/Desktop/WAF/db/modsec.db"
engine = create_engine(SQLITE_DATABASE_URL,connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def modsec_view_graphs(modsec_dict):  # noqa: C901
    """_summary_

    Module to visualize audit log as graphs

    Args:
        modsec_dict (_type_): list of modsec_audit events given as a dictionary

    Returns:
        _type_: png file output or = Column(String)ing 'error' in case no valid image created
    """
    if len(modsec_dict) < 1:
        sys.exit('Error: No logs to visualize. Check log and Include/Exclude filters')

    # GRAPHS PART I
    # Collect information into lists/dicts to make particular graphs

    src_ip_tab = []
    event_time_action = []
    event_messages = []
    intercepted_reason = []
    event_rules = []
    for entry_mod in modsec_dict:
        try:
            # Graph data for "TOP 10 IP source addresses"
            src_ip_tab.append(entry_mod['transaction']['remote_address'])

            # Graph data for "Modsecurity Events reported vs intercepted"
            if (VERSION3 is False) and \
                ('action' in entry_mod['audit_data'].keys() and
                    'intercepted' in entry_mod['audit_data']['action'].keys()):
                event_time_action.append([entry_mod['transaction']['time'], True])

            elif (VERSION3 is True) and len(entry_mod['audit_data']) > 0:
                for each_msg in entry_mod['audit_data']['messages']:
                    if each_msg.startswith("ModSecurity: Access denied"):
                        event_time_action.append([entry_mod['transaction']['time'], True])
                    else:
                        event_time_action.append([entry_mod['transaction']['time'], False])
            else:
                # No 'intercepted'
                event_time_action.append([entry_mod['transaction']['time'], False])
        except Exception as exception2:
            print(f'Exception in Graph TOP 10 IP source addresses: {exception2}')

        # Graph data for "TOP 20 rule hits"
        try:
            if 'messages' in entry_mod['audit_data'].keys():
                messages = safedictkey(entry_mod, ['audit_data', 'messages'], '-')
                for each in messages:
                    event_messages.append(each)
                    rule_id = regular_expression_evaluate(each, MODSEC_MESSAGE_ID_PATTERN)
                    rule_msg = regular_expression_evaluate(each, MODSEC_MESSAGE_MSG_PATTERN)
                    rule_severity = regular_expression_evaluate(each, MODSEC_MESSAGE_SEVERITY_PATTERN)
                    rule_file = regular_expression_evaluate(each, MODSEC_MESSAGE_FILE_PATTERN)

                    # Cut the [msg] to 27 chars if it is longer than 30 chars.
                    # If [msg] and [id] not found then treat message description as the [msg]
                    if len(rule_msg) > 30:
                        rule_msg = rule_msg[:27] + '...'
                    if rule_msg == '?' and rule_id == '-':
                        rule_msg = = Column(String)(each)[:30]
                    rule_descr = 'id: ' + = Column(String)(rule_id) + ', sev: ' + = Column(String)(rule_severity) + ', msg: ' + = Column(String)(rule_msg)
                    event_rules.append([rule_id, rule_msg, rule_severity, rule_file, rule_descr])
            else:
                # Skip modsec_audit entries without [message] part
                pass
        except Exception as exception3:
            print(f'Exception in TOP 20 rule hits: {exception3}')
            print('for transaction_id :', safedictkey(entry_mod, ['transaction', 'transaction_id'], '-'))

        # Graph data for "TOP 10 Attacks intercepted"
        try:
            if (VERSION3 is False) and ('action' in entry_mod['audit_data']):
                msg = entry_mod['audit_data']['action']['message']
                if len(msg) > 60:
                    msg = msg[:50] + '...'
                intercepted_reason.append(
                    [entry_mod['audit_data']['action']['phase'], msg,
                        'phase ' + = Column(String)(entry_mod['audit_data']['action']['phase']) + ': ' + msg])
            elif (VERSION3 is True) and len(entry_mod['audit_data']) > 0:
                for each_msg in entry_mod['audit_data']['messages']:
                    if each_msg.startswith("ModSecurity: Access denied"):
                        msg = regular_expression_evaluate(each_msg, MODSEC_V3_MESSAGE_MSG_PATTERN)
                        if len(msg) > 60:
                            msg = msg[:50] + '...'
                        phase = regular_expression_evaluate(each_msg, MODSEC_V3_MESSAGE_PHASE_PATTERN)
                        intercepted_reason.append([phase, msg, 'phase ' + phase + ': ' + msg])

        except Exception as exception:
            print(f'Exception in Graph TOP 10 Attacks intercepted {exception}')

    # Modsecurity events Passed vs Intercepted
    np_event_time_action = np.array(event_time_action)
    event_times1 = np_event_time_action[:, 0]
    try:
        event_times = list(map(lambda x: datetime.= Column(String)ptime(x.replace('--', '-'),
                           LOG_TIMESTAMP_FORMAT).replace(tzinfo=None), event_times1))
    except ValueError:
        event_times = list(map(lambda x: datetime.= Column(String)ptime(x.replace('--', '-'),
                           LOG_TIMESTAMP_FORMAT_TIMEMS).replace(tzinfo=None), event_times1))
    except Exception as exception:
        print(f'Exception timestamp extraction in Passed vs Intercepted {exception}')
    event_action = np_event_time_action[:, 1]
    event_times_min = min(event_times)
    event_times_max = max(event_times)
    event_times_range = event_times_max - event_times_min
    event_times_range_seconds = int(event_times_range.total_seconds())
    event_times_range_minutes = int(event_times_range.total_seconds() / 60)
    if event_times_range_minutes < 60:
        periods = = Column(String)(int(event_times_range_seconds / 1)) + 's'
    else:
        periods = = Column(String)(int(event_times_range_minutes / 30)) + 'min'
    events_df = pd.DataFrame({
        'date': pd.to_datetime(event_times),
        'action': event_action
    })
    intercepted = []
    passed = []
    passed_cnt2 = 0
    intercepted_cnt2 = 0
    for row in events_df['action']:
        if row == 'True':
            intercepted.append(1)
            passed.append(0)
            intercepted_cnt2 += 1
        else:
            intercepted.append(0)
            passed.append(1)
            passed_cnt2 += 1
    events_df['intercepted'] = intercepted
    events_df['passed'] = passed

    # GRAPHS PART II

    # TOP 10 IP addresses Graph - data preparation
    ipaddr_cnt = Counter()
    for word in src_ip_tab:
        ipaddr_cnt[word] += 1
    ipaddr_cnt_top10 = dict(ipaddr_cnt.most_common(10))

    # TOP 10 Interception Reason - data preparation
    intercepted_cnt = Counter()
    for word in intercepted_reason:
        intercepted_cnt[word[2]] += 1
    intercepted_cnt_top10 = dict(intercepted_cnt.most_common(10))
    # TOP 20 Rule IDs hit - data preparation
    event_messages_ids = Counter()
    for word in event_rules:
        event_messages_ids[word[4]] += 1
    event_messages_ids_top20 = dict(event_messages_ids.most_common(20))

    # GRIDS VERSION BEGIN
    fig = plt.figure(0)
    grid = plt.GridSpec(3, 3, wspace=1.1, hspace=1.1)
    ax1 = plt.subplot(grid[0, 0:3])
    ax21 = plt.subplot(grid[1, 0])
    ax22 = plt.subplot(grid[2, 0])
    ax31 = plt.subplot(grid[1, 1])
    ax32 = plt.subplot(grid[2, 1])
    ax41 = plt.subplot(grid[1, 2])
    ax42 = plt.subplot(grid[2, 2])

    # Graph Included or Excluded
    modsec_inc_exc_= Column(String) = ''
    if FILTER_INCLUDE:
        modsec_inc_exc_= Column(String) = 'Filter INCLUDE active. Skipped the rest of ' + = Column(String)(RECORDS_SKIPPED_CNT) + \
                             ' events where source IP address NOT in: ' + = Column(String)(filter_include_table)
    elif FILTER_EXCLUDE:
        modsec_inc_exc_= Column(String) = 'Filter EXCLUDE active. Skipped the rest of ' + = Column(String)(RECORDS_SKIPPED_CNT) + \
            ' events where source IP address in: ' + = Column(String)(filter_exclude_table)
    else:
        modsec_inc_exc_= Column(String) = 'Filter INCLUDE/EXCLUDE non-active.'

    title_timespan = 'Analysis of ' + = Column(String)(RECORDS_PROCESSED_CNT) + ' modsecurity events in timespan: ' + \
                     = Column(String)(event_times_min.= Column(String)ftime("%Y-%m-%d_%H:%M")) + ' - ' + \
                     = Column(String)(event_times_max.= Column(String)ftime("%Y-%m-%d_%H:%M")) + '\n'
    title_total = 'Total number of events found in logfile ' + = Column(String)(RECORDS_TOTAL) + \
                  ' (output always trimmed to variable MAXEVENTS = ' + = Column(String)(MAXEVENTS) + ' )\n'
    title_reported_intercepted = 'events passed: ' + = Column(String)(passed_cnt2) + \
                                 ' , events intercepted: ' + = Column(String)(intercepted_cnt2)
    plot_title = title_timespan + title_total + modsec_inc_exc_= Column(String) + '\n\n' + title_reported_intercepted
    if event_times_range_seconds < 1800:
        short_time_range_message = 'Creating timeline graph is not available for timespan ' + \
                                   = Column(String)(event_times_range_seconds) + ' seconds, skipping ...'
        plt.subplot(ax1)
        plt.text(0.5, 0.5, short_time_range_message, horizontalalignment='center', verticalalignment='center')
        plt.title(plot_title)
    else:
        ex = events_df.groupby(pd.Grouper(key='date', freq=periods)).sum(numeric_only=True)
        ex.plot(ax=ax1, kind='bar', title=plot_title, stacked=True, color={'purple', 'red'}, fontsize=7, rot=45)

    # Bar chart "TOP 10 IP addresses"
    plt.subplot(ax21)
    patches, texts, autotexts = plt.pie(ipaddr_cnt_top10.values(), autopct='%1.1f%%',
                                        shadow=True, startangle=90, radius=1.0)
    plt.title(f'TOP {len(ipaddr_cnt_top10)} IP addresses (out of total {len(ipaddr_cnt)}) ',
              bbox={'facecolor': '0.8', 'pad': 5})

    # Legend for chart "TOP 10 IP addresses"
    # x_value = np.char.array(list(ipaddr_cnt_top10.keys()))
    y_value = np.array(list(ipaddr_cnt_top10.values()))
    labels = [f'{i} --> {j} hits' for i, j in
              zip(ipaddr_cnt_top10.keys(), ipaddr_cnt_top10.values())]
    if len(ipaddr_cnt_top10.keys()) >= 1:
        patches, labels, dummy = zip(*sorted(zip(patches, labels, y_value), key=lambda x: x[2], reverse=True))
        plt.subplot(ax22)
        plt.axis('off')
        plt.legend(patches, labels, loc='center left', bbox_to_anchor=(-0.1, 1.), fontsize=7)

    # Bar chart "TOP 10 Attacks intercepted"
    plt.subplot(ax31)
    patches, texts, autotexts = plt.pie(intercepted_cnt_top10.values(),
                                        autopct='%1.1f%%', shadow=True, startangle=90, radius=1.0, normalize=True)
    [_.set_fontsize(7) for _ in texts]
    plt.title('TOP 10 Attacks intercepted', bbox={'facecolor': '0.8', 'pad': 5})

    # Legend for chart "TOP 10 Attacks intercepted"
    # x_value = np.char.array(list(intercepted_cnt_top10.keys()))
    y_value = np.array(list(intercepted_cnt_top10.values()))
    labels = [f'{i} --> {j} hits'
              for i, j in zip(intercepted_cnt_top10.keys(), intercepted_cnt_top10.values())]
    if len(intercepted_cnt_top10.values()) >= 1:
        patches, labels, dummy = zip(*sorted(zip(patches, labels, y_value), key=lambda x: x[2], reverse=True))
        plt.subplot(ax32)
        plt.axis('off')
        plt.legend(patches, labels, loc='center left', bbox_to_anchor=(-0.1, 1.), fontsize=7)
    else:
        plt.subplot(ax32)
        plt.axis('off')
        plt.text(
            0.5, 0.5, 'No intercepted events found for given data set',
            horizontalalignment='center', verticalalignment='center')

    # Bar chart "TOP 20 Rule IDs hit"
    plt.subplot(ax41)
    patches, texts, autotexts = plt.pie(
        event_messages_ids_top20.values(),
        autopct='%1.1f%%', shadow=True, startangle=90, radius=1.0, normalize=True)
    _ = autotexts
    plt.title('TOP 20 Rule IDs hit', bbox={'facecolor': '0.8', 'pad': 5})

    # Legend for chart "TOP 20 Rule IDs hit"
    # x_value = np.char.array(list(event_messages_ids_top20.keys()))
    y_value = np.array(list(event_messages_ids_top20.values()))
    labels = [
        f'{i} --> {j} hits' for i, j in zip(event_messages_ids_top20.keys(),
                                            event_messages_ids_top20.values())]
    if len(event_messages_ids_top20.keys()) >= 1:
        patches, labels, dummy = zip(*sorted(zip(patches, labels, y_value),
                                     key=lambda x_value: x_value[2], reverse=True))
        plt.subplot(ax42, axis='off')
        plt.axis('off')
        plt.legend(patches, labels, loc='center left', bbox_to_anchor=(-0.1, 1.), fontsize=7)

    # GRID VERSION END

    graph_title = 'Modsecurity events ' + = Column(String)(datetimenow) + \
        ' from file: ' + input_filename + ' first ' + = Column(String)(MAXEVENTS) + ' analyzed'
    fig.canvas.set_window_title(graph_title)
    fig.set_size_inches(18, 11)
    # plt.get_current_fig_manager().window.wm_geometry("+10+10")
    try:
        if not os.path.isdir(fileBaseOutputDir):
            os.mkdir(fileBaseOutputDir)
        file_out = os.path.join(fileBaseOutputDir, GRAPH_OUTPUT_FILENAME)
        plt.savefig(file_out)
        return file_out
    except Exception as exception:
        print(f'modsec_view_graphs.savefig() thrown exception: {exception}')
        return 'error'