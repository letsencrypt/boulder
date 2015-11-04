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
randAx.plot(0, 0, color='orange', label='value at quantile')
randAx.plot(0, 0, color='teal', label='count at quantile')
handles, labels = randAx.get_legend_handles_labels()
x = [0, 0.1, 0.5, 0.75, 0.9, 0.99, 0.999, 0.9999, 0.99999]
xStandIn = range(len(x))

# big ol' plotting method
def plot_section(data, outputPath):
    h = len(data.keys())
    matplotlib.rcParams['figure.figsize'] = 24, 4 * h
    fig = plt.figure()
    fig.suptitle('placeholder for now', fontsize=20)
    fig.legend(handles, labels, loc=9, ncol=5, fontsize=16, framealpha=0)
    plt.subplots_adjust(wspace=0.275, hspace=0.5, top=0.95)

    i = 1
    for section in data.keys():
        ax = plt.subplot(h, 3, i)
        ax.set_title(section)
        i += 1
        ax2 = plt.subplot(h, 3, i)
        i += 1

        calls = pandas.DataFrame(data[section])
        calls['finished'] = pandas.to_datetime(calls['finished']).astype(datetime.datetime)
        calls['sent'] = pandas.to_datetime(calls['sent']).astype(datetime.datetime)
        calls['took'] = calls['took'].divide(1000000)

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

        ax3 = plt.subplot(h, 3, i)
        i += 1
        ax4 = ax3.twinx()
        qs = []
        counts = []
        for n, q in enumerate(x):
            tq = calls['took'].quantile(q)
            qs.append(tq)
            if n > 0:
                prev = qs[n-1]
                count = len(calls[calls['took'] >= prev])
                count -= len(calls[calls['took'] > tq])
            else:
                count = len(calls[calls['took'] == tq])
            counts.append(count)
        ax4.plot(xStandIn, qs, color='orange')
        ax3.plot(xStandIn, counts, color='teal')

        ax3.set_xticks(xStandIn)
        ax3.set_xticklabels([str(s) for s in x])
        ax3.grid(False)
        ax4.grid(False)
        ax3.set_ylabel('Count')
        ax4.set_ylabel('Latency (ms)')
        ax3.set_xlabel('Quantile')

        fig.savefig(outputPath)

# and the main event
parser = argparse.ArgumentParser()
parser.add_argument('chartData', type=str, help='Path to file containing JSON chart output from load-generator')
parser.add_argument('--output', type=str, help='Path to save output to', default='latency-chart.png')
args = parser.parse_args()

with open(args.chartData) as data_file:
    stuff = json.load(data_file)

if not stuff.get('metrics', False):
    print "BAD"
    os.exit(1)

plot_section(stuff['metrics'], args.output)
