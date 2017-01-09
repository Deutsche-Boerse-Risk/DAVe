import {Component} from '@angular/core';
import {ActivatedRoute} from '@angular/router';

import {ErrorResponse} from '../abstract.http.service';
import {TotalMarginService} from './total.margin.service';
import {TotalMarginData} from './total.margin.types';

import {AbstractLatestListComponent} from '../abstract.latest.list.component';

export const routingKeys: string[] = ['clearer', 'pool', 'member', 'account', 'ccy'];

export const exportKeys: string[] = ['clearer', 'pool', 'member', 'account', 'ccy', 'bizDt', 'unadjustedMargin',
    'adjustedMargin', 'received'];

const defaultOrdering = ['-adjustedMargin', 'clearer', 'pool', 'member', 'account', 'ccy'];

@Component({
    moduleId: module.id,
    templateUrl: 'total.margin.requirement.latest.component.html',
    styleUrls: ['../common.component.css']
})
export class TotalMarginRequirementLatestComponent extends AbstractLatestListComponent<TotalMarginData> {

    constructor(private totalMarginService: TotalMarginService,
                route: ActivatedRoute) {
        super(route);
    }

    protected loadData(): void {
        this.totalMarginService.getTotalMarginLatest(this.routeParams['clearer'], this.routeParams['pool'],
            this.routeParams['member'], this.routeParams['account'], this.routeParams['ccy'])
            .then((rows: TotalMarginData[]) => {
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

    protected get exportKeys(): string[] {
        return exportKeys;
    }

    protected get routingKeys(): string[] {
        return routingKeys;
    }

    protected get rootRouteTitle(): string {
        return 'Latest Total Margin Requirements';
    }

    protected get rootRoutePath(): string {
        return '/totalMarginRequirementLatest';
    }

}