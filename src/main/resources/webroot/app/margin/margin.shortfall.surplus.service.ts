import {Injectable} from '@angular/core';
import {AbstractHttpService} from '../abstract.http.service';
import {Http} from '@angular/http';

import {AuthHttp} from 'angular2-jwt';

import {
    MarginShortfallSurplusServerData, MarginShortfallSurplusBase, MarginShortfallSurplusData
} from './margin.types';

const marginShortfallSurplusURL: string = '/mss/latest';
const marginShortfallSurplusLatestURL: string = '/mss/latest/:0/:1/:2/:3';
const marginShortfallSurplusHistoryURL: string = '/mss/history/:0/:1/:2/:3/:4';

@Injectable()
export class MarginShortfallSurplusService extends AbstractHttpService<MarginShortfallSurplusServerData[]> {

    constructor(http: Http, authHttp: AuthHttp) {
        super(http, authHttp);
    }

    public getMarginShortfallSurplusData(): Promise<MarginShortfallSurplusBase> {
        return new Promise((resolve, reject) => {
            this.get({resourceURL: marginShortfallSurplusURL}).subscribe((data: MarginShortfallSurplusServerData[]) => {
                if (!data) {
                    resolve({});
                    return;
                }
                let result: MarginShortfallSurplusBase = {
                    shortfallSurplus: 0,
                    marginRequirement: 0,
                    securityCollateral: 0,
                    cashBalance: 0,
                    marginCall: 0,
                };

                for (let index = 0; index < data.length; ++index) {
                    result.shortfallSurplus += data[index].shortfallSurplus;
                    result.marginRequirement += data[index].marginRequirement;
                    result.securityCollateral += data[index].securityCollateral;
                    result.cashBalance += data[index].cashBalance;
                    result.marginCall += data[index].marginCall;
                }
                resolve(result);
            }, reject);
        });
    }

    public getShortfallSurplusLatest(clearer: string = '*', pool: string = '*', member: string = '*',
                                     clearingCcy: string = '*'): Promise<MarginShortfallSurplusData[]> {
        return new Promise((resolve, reject) => {
            this.get({
                resourceURL: marginShortfallSurplusLatestURL,
                params: [
                    clearer,
                    pool,
                    member,
                    clearingCcy
                ]
            }).subscribe((data: MarginShortfallSurplusServerData[]) => {
                let result: MarginShortfallSurplusData[] = [];
                if (data) {
                    data.forEach((record: MarginShortfallSurplusServerData) => {
                        let row: MarginShortfallSurplusData = {
                            clearer: record.clearer,
                            member: record.member,
                            bizDt: record.bizDt,
                            received: new Date(record.received),
                            ccy: record.ccy,
                            cashBalance: record.cashBalance,
                            clearingCcy: record.clearingCcy,
                            marginCall: record.marginCall,
                            marginRequirement: record.marginRequirement,
                            pool: record.pool,
                            poolType: record.poolType,
                            shortfallSurplus: record.shortfallSurplus,
                            securityCollateral: record.securityCollateral
                        };

                        result.push(row);
                    });
                    resolve(result);
                } else {
                    resolve([]);
                }
            }, reject);
        });
    }

    public getShortfallSurplusHistory(clearer: string, pool: string, member: string, clearingCcy: string, ccy: string): Promise<MarginShortfallSurplusData[]> {
        return new Promise((resolve, reject) => {
            this.get({
                resourceURL: marginShortfallSurplusHistoryURL,
                params: [
                    clearer,
                    pool,
                    member,
                    clearingCcy,
                    ccy
                ]
            }).subscribe((data: MarginShortfallSurplusServerData[]) => {
                let result: MarginShortfallSurplusData[] = [];
                if (data) {
                    data.forEach((record: MarginShortfallSurplusServerData) => {
                        let row: MarginShortfallSurplusData = {
                            clearer: record.clearer,
                            member: record.member,
                            bizDt: record.bizDt,
                            received: new Date(record.received),
                            ccy: record.ccy,
                            cashBalance: record.cashBalance,
                            clearingCcy: record.clearingCcy,
                            marginCall: record.marginCall,
                            marginRequirement: record.marginRequirement,
                            pool: record.pool,
                            poolType: record.poolType,
                            shortfallSurplus: record.shortfallSurplus,
                            securityCollateral: record.securityCollateral
                        };

                        result.push(row);
                    });
                    resolve(result);
                } else {
                    resolve([]);
                }
            }, reject);
        });
    }
}