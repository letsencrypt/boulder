#!/usr/bin/python

import matplotlib.pyplot as plt
import datetime
import json
import pandas
import matplotlib
import argparse
import os
matplotlib.style.use('ggplot')

# sacrifical plot for single legend
matplotlib.rcParams['figure.figsize'] = 1, 1
randFig = plt.figure()
randAx = plt.subplot()
randAx.plot(0, 0, color='green', label='good', marker='+')
randAx.plot(0, 0, color='red', label='failed', marker='x')
randAx.plot(0, 0, color='black', label='sent', linestyle='--')
randAx.plot(0, 0, color='green', label='50th quantile')
randAx.plot(0, 0, color='yellow', label='90th quantile')
randAx.plot(0, 0, color='orange', label='99th quantile')
randAx.plot(0, 0, color='red', label='99.9th quantile')
handles, labels = randAx.get_legend_handles_labels()

# big ol' plotting method
def plot_section(data, started, stopped, title, outputPath):
    h = len(data.keys())
    matplotlib.rcParams['figure.figsize'] = 18, 3 * h

    fig, axes = plt.subplots(h, 3)
    fig.legend(handles, labels, loc=9, ncol=7, fontsize=16, framealpha=0)
    fig.suptitle(title, fontsize=20)
    plt.subplots_adjust(wspace=0.275, hspace=0.5, top=0.95, left=0.05, right=0.95, bottom=0.04)

    # figure out left and right datetime bounds from started and stopped
    started = pandas.to_datetime(started)
    stopped = pandas.to_datetime(stopped)

    i = 0
    for section in data.keys():
        ax = axes[i][0]
        ax.set_title(section)
        ax.set_xlim(started, stopped)
        ax2 = axes[i][1]
        ax2.set_xlim(started, stopped)

        calls = pandas.DataFrame(data[section])
        calls['finished'] = pandas.to_datetime(calls['finished']).astype(datetime.datetime)
        calls['sent'] = pandas.to_datetime(calls['sent']).astype(datetime.datetime)
        calls['took'] = calls['took'].divide(1000000)
        tookMax = calls['took'].max()
        ax.set_ylim(0, tookMax+tookMax*0.1)

        groups = calls.groupby('type')
        if groups.groups.get('error', False):
            bad = groups.get_group('error')
            ax.plot_date(bad['finished'], bad['took'], color='red', marker='x', label='error')

            bad_rate = bad.set_index('finished')
            bad_rate['rate'] = [0] * len(bad_rate.index)
            bad_rate = bad_rate.resample('10S', how='count')
            bad_rate['rate'] = bad_rate['rate'].divide(10)
            rateMax = bad_rate['rate'].max()
            ax2.plot_date(bad_rate.index, bad_rate['rate'], linestyle='-', marker='', color='red', label='error')
        if groups.groups.get('good', False):
            good = groups.get_group('good')
            ax.plot_date(good['finished'], good['took'], color='green', marker='+', label='good')

            good_rate = good.set_index('finished')
            good_rate['rate'] = [0] * len(good_rate.index)
            good_rate = good_rate.resample('10S', how='count')
            good_rate['rate'] = good_rate['rate'].divide(10)
            rateMax = good_rate['rate'].max()
            ax2.plot_date(good_rate.index, good_rate['rate'], linestyle='-', marker='', color='green', label='good')

        ax.grid(False)
        ax.set_ylabel('Latency (ms)')

        sent_rate = pandas.DataFrame(calls['sent'])
        sent_rate = sent_rate.set_index('sent')
        sent_rate['rate'] = [0] * len(sent_rate.index)
        sent_rate = sent_rate.resample('10S', how='count')
        sent_rate['rate'] = sent_rate['rate'].divide(10)
        if sent_rate['rate'].max() > rateMax:
            rateMax = sent_rate['rate'].max()
        ax2.plot_date(sent_rate.index, sent_rate['rate'], linestyle='--', marker='', color='black', label='sent')
        ax2.set_ylim(0, rateMax+rateMax*0.1)
        ax2.grid(False)
        ax2.set_ylabel('Rate (per second)')

        ax3 = axes[i][2]
        ax3.set_xlim(started, stopped)
        ax3.set_ylim(0, tookMax+tookMax*0.1)

        calls = calls.set_index('finished')
        calls = calls.sort_index()
        calls['50'] = pandas.rolling_quantile(calls['took'], 10, 0.5).fillna(0)
        calls['90'] = pandas.rolling_quantile(calls['took'], 10, 0.9).fillna(0)
        calls['99'] = pandas.rolling_quantile(calls['took'], 10, 0.99).fillna(0)
        calls['999'] = pandas.rolling_quantile(calls['took'], 10, 0.999).fillna(0)
        ax3.plot(calls.index, calls['50'], color='green')
        ax3.plot(calls.index, calls['90'], color='yellow')
        ax3.plot(calls.index, calls['99'], color='orange')
        ax3.plot(calls.index, calls['999'], color='red')

        ax3.grid(False)
        ax3.set_ylabel('Latency (ms)')

        i += 1

    for ax in fig.axes:
        matplotlib.pyplot.sca(ax)
        plt.xticks(rotation=30, ha='right')

    fig.savefig(outputPath)

# and the main event
parser = argparse.ArgumentParser()
parser.add_argument('chartData', type=str, help='Path to file containing JSON chart output from load-generator')
parser.add_argument('--output', type=str, help='Path to save output to', default='latency-chart.png')
args = parser.parse_args()

with open(args.chartData) as data_file:
    stuff = json.load(data_file)

if not stuff.get('metrics', False) or not stuff.get('started', False) or not stuff.get('stopped', False) or not stuff.get('title', False):
    print "BAD"
    os.exit(1)

plot_section(stuff['metrics'], stuff['started'], stuff['stopped'], stuff['title'], args.output)
