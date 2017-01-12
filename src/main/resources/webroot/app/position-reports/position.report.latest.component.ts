import {Component} from '@angular/core';
import {ActivatedRoute} from '@angular/router';

import {ErrorResponse} from '../abstract.http.service';
import {PositionReportData} from './position.report.types';
import {PositionReportsService} from './position.reports.service';

import {AbstractLatestListComponent} from '../list/abstract.latest.list.component';

export const routingKeys: string[] = ['clearer', 'member', 'account', 'class', 'symbol', 'putCall',
    'strikePrice', 'optAttribute', 'maturityMonthYear'];

export const exportKeys: string[] = ['clearer', 'member', 'account', 'bizDt', 'symbol', 'putCall', 'maturityMonthYear',
    'strikePrice', 'optAttribute', 'crossMarginLongQty', 'crossMarginShortQty', 'optionExcerciseQty',
    'optionAssignmentQty', 'allocationTradeQty', 'deliveryNoticeQty', 'clearingCcy', 'mVar', 'compVar',
    'compCorrelationBreak', 'compCompressionError', 'compLiquidityAddOn', 'compLongOptionCredit', 'productCcy',
    'variationMarginPremiumPayment', 'premiumMargin', 'delta', 'gamma', 'vega', 'rho', 'theta', 'received', 'class',
    'underlying', 'netLS', 'netEA'];

const defaultOrdering = ['-absCompVar', 'clearer', 'member', 'account', 'symbol', 'putCall', 'strikePrice',
    'optAttribute', 'maturityMonthYear'];

@Component({
    moduleId: module.id,
    templateUrl: 'position.report.latest.component.html',
    styleUrls: ['../common.component.css']
})
export class PositionReportLatestComponent extends AbstractLatestListComponent<PositionReportData> {

    constructor(private positionReportsService: PositionReportsService,
                route: ActivatedRoute) {
        super(route);
    }

    protected loadData(): void {
        this.positionReportsService.getPositionReportLatest(this.routeParams['clearer'], this.routeParams['member'],
            this.routeParams['account'], this.routeParams['class'], this.routeParams['symbol'],
            this.routeParams['putCall'], this.routeParams['strikePrice'], this.routeParams['optAttribute'],
            this.routeParams['maturityMonthYear'])
            .then((rows: PositionReportData[]) => {
                this.processData(rows);
            })
            .catch((err: ErrorResponse) => {
                this.errorMessage = 'Server returned status ' + err.status;
                this.initialLoad = false;
            });
    }

    public get defaultOrdering(): string[] {
        return defaultOrdering;
    }

    public get exportKeys(): string[] {
        return exportKeys;
    }

    protected get routingKeys(): string[] {
        return routingKeys;
    }

    public get rootRouteTitle(): string {
        return 'Latest Position Reports';
    }

    protected get rootRoutePath(): string {
        return '/positionReportLatest';
    }

}